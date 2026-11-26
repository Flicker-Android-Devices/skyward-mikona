//! Listing flashable ROM and firmware zip packages hosted on SourceForge
//! for a specific device codename.

use crate::release::Release;
use anyhow::{ensure, Context, Result};
use roxmltree::Document;
use std::collections::BTreeSet;

/// SourceForge caps a single RSS response at 100 items.
const RSS_LIMIT: usize = 100;
const MAX_DEPTH: usize = 6;
const MEDIA_NS: &str = "http://video.search.yahoo.com/mrss/";

/// A parsed SourceForge project files root/subdirectory URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub project: String,
    /// Normalized leading-slash path inside `/files`, e.g. `"/"`, `"/ROM"`,
    /// or `"/Firmware/thyme"`.
    pub base_path: String,
}

/// One file entry read from a SourceForge RSS feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub url: String,
    pub length: u64,
    pub md5: String,
    pub pub_date: u64,
}

/// A recovery-flashable zip package matched for a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Relative folder segments between `base_path` and filename (excluding
    /// the device codename), joined with `" / "`.
    pub channel: String,
    pub release: Release,
    pub pub_date: u64,
}

impl Source {
    /// Parse a SourceForge files URL such as
    /// `https://sourceforge.net/projects/flickerdev/files/ROM/`.
    pub fn parse_url(url: &str) -> Result<Self> {
        let clean = url.split(['?', '#']).next().unwrap_or_default();
        let rest = clean
            .strip_prefix("https://sourceforge.net/projects/")
            .with_context(|| format!("{url} is not a SourceForge project URL"))?;
        let (project, after) = rest
            .split_once("/files")
            .with_context(|| format!("{url} is not a SourceForge files URL"))?;
        ensure!(!project.is_empty() && !project.contains('/'), "{url} names no SourceForge project");
        let subpath = after.strip_suffix("/download").unwrap_or(after).trim_matches('/');
        let base_path = if subpath.is_empty() { "/".to_string() } else { format!("/{subpath}") };
        Ok(Self { project: project.to_string(), base_path })
    }

    pub fn rss_url(&self, path: &str) -> String {
        format!("https://sourceforge.net/projects/{}/rss?path={}", self.project, encode_path(path))
    }

    pub fn files_url(&self, path: &str) -> String {
        let encoded = encode_path(path);
        if encoded == "/" {
            format!("https://sourceforge.net/projects/{}/files/", self.project)
        } else {
            format!("https://sourceforge.net/projects/{}/files{encoded}/", self.project)
        }
    }
}

fn encode_path(path: &str) -> String {
    let mut out = String::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        for &b in seg.as_bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    if out.is_empty() {
        "/".into()
    } else {
        out
    }
}

/// Fetch all recovery-flashable `.zip` packages under `url` that match `codename`,
/// ordered newest first.
pub fn fetch(agent: &ureq::Agent, url: &str, codename: &str) -> Result<Vec<Package>> {
    let source = Source::parse_url(url)?;
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    collect_entries(agent, &source, &source.base_path, codename, &mut seen, &mut entries, 0)?;
    Ok(packages(&entries, &source.base_path, codename))
}

fn get_text(agent: &ureq::Agent, url: &str) -> Result<String> {
    let mut response = agent.get(url).call().with_context(|| format!("fetch {url}"))?;
    let status = response.status();
    ensure!(status.is_success(), "{url} answered {status}");
    response.body_mut().read_to_string().with_context(|| format!("read {url}"))
}

fn collect_entries(
    agent: &ureq::Agent,
    source: &Source,
    dir: &str,
    codename: &str,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<Entry>,
    depth: usize,
) -> Result<()> {
    let xml = get_text(agent, &source.rss_url(dir))?;
    let items = parse_rss(&xml).with_context(|| format!("parse SourceForge RSS for {dir}"))?;
    if items.len() < RSS_LIMIT || depth >= MAX_DEPTH {
        for item in items {
            if seen.insert(item.path.clone()) {
                out.push(item);
            }
        }
        return Ok(());
    }
    // RSS capped out at 100 items: keep any direct child files of `dir` and
    // walk subdirectories via the HTML index so older builds are not missed.
    for item in items {
        let parent = item.path.rsplit_once('/').map(|(p, _)| if p.is_empty() { "/" } else { p }).unwrap_or("/");
        if parent == dir && seen.insert(item.path.clone()) {
            out.push(item);
        }
    }
    let html = get_text(agent, &source.files_url(dir))?;
    let folders = parse_folders(&html);
    let has_device_dir = !path_has_segment(dir, codename) && folders.iter().any(|f| f.eq_ignore_ascii_case(codename));
    for folder in folders {
        if has_device_dir && !folder.eq_ignore_ascii_case(codename) {
            continue;
        }
        let child = if dir == "/" { format!("/{folder}") } else { format!("{dir}/{folder}") };
        collect_entries(agent, source, &child, codename, seen, out, depth + 1)?;
    }
    Ok(())
}

/// Parse `<item>` entries from a SourceForge RSS XML document.
pub fn parse_rss(xml: &str) -> Result<Vec<Entry>> {
    let doc = Document::parse(xml).context("parse RSS XML")?;
    let mut out = Vec::new();
    for item in doc.descendants().filter(|n| n.has_tag_name("item")) {
        let Some(raw_title) = item.children().find(|n| n.has_tag_name("title")).and_then(|n| n.text()) else {
            continue;
        };
        let path = normalize_path(raw_title.trim());
        let link = item.children().find(|n| n.has_tag_name("link")).and_then(|n| n.text()).map(str::trim);
        let media = item.children().find(|n| n.tag_name().name() == "content" && n.tag_name().namespace() == Some(MEDIA_NS));
        let url = media
            .and_then(|m| m.attribute("url"))
            .or(link)
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
        let length = media.and_then(|m| m.attribute("filesize")).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        let md5 = media
            .into_iter()
            .flat_map(|m| m.children())
            .find(|n| n.tag_name().name() == "hash" && n.attribute("algo") == Some("md5"))
            .and_then(|n| n.text())
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let pub_date = item
            .children()
            .find(|n| n.has_tag_name("pubDate"))
            .and_then(|n| n.text())
            .and_then(parse_pub_date)
            .unwrap_or(0);
        if !path.is_empty() && !url.is_empty() {
            out.push(Entry { path, url, length, md5, pub_date });
        }
    }
    Ok(out)
}

/// Extract direct subfolder names from a SourceForge HTML directory page.
pub fn parse_folders(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for segment in html.split("<tr ").skip(1) {
        let Some(tag_end) = segment.find('>') else { continue };
        let attrs = &segment[..tag_end];
        if !attrs.contains("class=\"folder") && !attrs.contains("class='folder") {
            continue;
        }
        if let Some(name) = extract_attr(attrs, "title")
            && !name.is_empty()
            && !name.contains("{{")
            && !name.contains('/')
            && name != ".."
        {
            out.push(name);
        }
    }
    out
}

fn extract_attr(attrs: &str, attr: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let pat = format!("{attr}={quote}");
        if let Some(start) = attrs.find(&pat) {
            let rest = &attrs[start + pat.len()..];
            if let Some(end) = rest.find(quote) {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

/// Filter `entries` to flashable `.zip` packages under `base_path` for `codename`,
/// excluding fastboot packages and non-zip files, sorted newest first.
pub fn packages(entries: &[Entry], base_path: &str, codename: &str) -> Vec<Package> {
    let base = normalize_path(base_path);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in entries {
        let path = normalize_path(&entry.path);
        if !under_base(&path, &base) || !seen.insert(path.clone()) {
            continue;
        }
        if entry.length == 0 || entry.md5.len() != 32 || !entry.md5.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let Some((dir, name)) = path.rsplit_once('/') else { continue };
        let lower_name = name.to_ascii_lowercase();
        if !lower_name.ends_with(".zip") || lower_name.contains("fastboot") {
            continue;
        }
        if !matches_device(dir, name, codename) {
            continue;
        }
        let stem = &name[..name.len() - 4];
        let channel = relative_channel(dir, &base, codename);
        out.push(Package {
            channel,
            pub_date: entry.pub_date,
            release: Release {
                version: stem.to_string(),
                name: name.to_string(),
                urls: vec![entry.url.clone()],
                md5: entry.md5.to_ascii_lowercase(),
                size: String::new(),
                length: Some(entry.length),
            },
        });
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.pub_date));
    out
}

fn normalize_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else {
        format!("/{trimmed}")
    }
}

fn under_base(path: &str, base: &str) -> bool {
    if base == "/" {
        path.len() > 1
    } else {
        path.strip_prefix(base).is_some_and(|rest| rest.starts_with('/'))
    }
}

fn path_has_segment(path: &str, target: &str) -> bool {
    path.split('/').any(|s| s.eq_ignore_ascii_case(target))
}

fn matches_device(dir: &str, filename: &str, codename: &str) -> bool {
    path_has_segment(dir, codename)
        || filename.split(['_', '-', '.']).any(|tok| tok.eq_ignore_ascii_case(codename))
}

fn relative_channel(dir: &str, base: &str, codename: &str) -> String {
    let rel = if base == "/" {
        dir.trim_start_matches('/')
    } else {
        dir.strip_prefix(base).unwrap_or(dir).trim_start_matches('/')
    };
    rel.split('/')
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case(codename))
        .collect::<Vec<_>>()
        .join(" / ")
}

/// Parse an RFC-2822-like `<pubDate>` (e.g. `"Wed, 24 Jun 2026 18:38:16 UT"`)
/// into a packed `YYYYMMDDHHMMSS` integer for sorting.
fn parse_pub_date(raw: &str) -> Option<u64> {
    let after_day = raw.split(',').nth(1).unwrap_or(raw).trim();
    let mut parts = after_day.split_whitespace();
    let day: u64 = parts.next()?.parse().ok()?;
    let month: u64 = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: u64 = parts.next()?.parse().ok()?;
    let mut hms = parts.next()?.split(':');
    let hour: u64 = hms.next()?.parse().ok()?;
    let min: u64 = hms.next()?.parse().ok()?;
    let sec: u64 = hms.next()?.parse().ok()?;
    Some((((((year * 100 + month) * 100 + day) * 100 + hour) * 100 + min) * 100) + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RSS: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<rss xmlns:media="http://video.search.yahoo.com/mrss/" version="2.0">
  <channel>
    <item>
      <title><![CDATA[/ROM/sixteen/thyme/qpr2/PixelOS/20260625/ksu_boot.img]]></title>
      <link>https://sourceforge.net/projects/flickerdev/files/ROM/sixteen/thyme/qpr2/PixelOS/20260625/ksu_boot.img/download</link>
      <pubDate>Wed, 24 Jun 2026 19:06:50 UT</pubDate>
      <media:content url="https://sourceforge.net/projects/flickerdev/files/ROM/sixteen/thyme/qpr2/PixelOS/20260625/ksu_boot.img/download" filesize="201326592"><media:hash algo="md5">5b118b3ff6794a5ad23f4afc9bd6f323</media:hash></media:content>
    </item>
    <item>
      <title><![CDATA[/ROM/sixteen/thyme/qpr2/PixelOS/20260625/PixelOS_thyme-16.2-20260624-1725.zip.md5sum]]></title>
      <link>https://sourceforge.net/projects/flickerdev/files/ROM/sixteen/thyme/qpr2/PixelOS/20260625/PixelOS_thyme-16.2-20260624-1725.zip.md5sum/download</link>
      <pubDate>Wed, 24 Jun 2026 18:38:36 UT</pubDate>
      <media:content url="https://sourceforge.net/projects/flickerdev/files/ROM/sixteen/thyme/qpr2/PixelOS/20260625/PixelOS_thyme-16.2-20260624-1725.zip.md5sum/download" filesize="71"><media:hash algo="md5">227296801125818cdd12eacdbed923c4</media:hash></media:content>
    </item>
    <item>
      <title><![CDATA[/ROM/fifteen/thyme/PixelOS/20250718/PixelOS_thyme-15.0-20250718-1351.zip]]></title>
      <link>https://sourceforge.net/projects/flickerdev/files/ROM/fifteen/thyme/PixelOS/20250718/PixelOS_thyme-15.0-20250718-1351.zip/download</link>
      <pubDate>Fri, 18 Jul 2025 14:16:24 UT</pubDate>
      <media:content url="https://sourceforge.net/projects/flickerdev/files/ROM/fifteen/thyme/PixelOS/20250718/PixelOS_thyme-15.0-20250718-1351.zip/download" filesize="2530376751"><media:hash algo="md5">cbf625f55c4af5f7a11e0f576bbbd4c1</media:hash></media:content>
    </item>
    <item>
      <title><![CDATA[/ROM/fifteen/thyme/PixelOS/thyme_fastboot_fw_OS1.0.4.0.zip]]></title>
      <link>https://sourceforge.net/projects/flickerdev/files/ROM/fifteen/thyme/PixelOS/thyme_fastboot_fw_OS1.0.4.0.zip/download</link>
      <pubDate>Tue, 18 Feb 2025 10:00:00 UT</pubDate>
      <media:content url="https://sourceforge.net/projects/flickerdev/files/ROM/fifteen/thyme/PixelOS/thyme_fastboot_fw_OS1.0.4.0.zip/download" filesize="150000000"><media:hash algo="md5">11111111111111111111111111111111</media:hash></media:content>
    </item>
    <item>
      <title><![CDATA[/ROM/sixteen/thyme/qpr2/PixelOS/20260625/PixelOS_thyme-16.2-20260624-1725.zip]]></title>
      <link>https://sourceforge.net/projects/flickerdev/files/ROM/sixteen/thyme/qpr2/PixelOS/20260625/PixelOS_thyme-16.2-20260624-1725.zip/download</link>
      <pubDate>Wed, 24 Jun 2026 18:38:16 UT</pubDate>
      <media:content url="https://sourceforge.net/projects/flickerdev/files/ROM/sixteen/thyme/qpr2/PixelOS/20260625/PixelOS_thyme-16.2-20260624-1725.zip/download" filesize="2611868200"><media:hash algo="md5">f6b3e3cb34a5048166a3ac9dc2e25105</media:hash></media:content>
    </item>
    <item>
      <title><![CDATA[/ROM/fourteen/lmi/PixelOS_lmi-14.0-20241110-1122.zip]]></title>
      <link>https://sourceforge.net/projects/flickerdev/files/ROM/fourteen/lmi/PixelOS_lmi-14.0-20241110-1122.zip/download</link>
      <pubDate>Sun, 10 Nov 2024 11:22:00 UT</pubDate>
      <media:content url="https://sourceforge.net/projects/flickerdev/files/ROM/fourteen/lmi/PixelOS_lmi-14.0-20241110-1122.zip/download" filesize="2000000000"><media:hash algo="md5">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</media:hash></media:content>
    </item>
    <item>
      <title><![CDATA[/Firmware/thyme/fw_thyme_miui_THYME_OS1.0.4.0.TGACNXM_80dbab1cd4_13.0.zip]]></title>
      <link>https://sourceforge.net/projects/flickerdev/files/Firmware/thyme/fw_thyme_miui_THYME_OS1.0.4.0.TGACNXM_80dbab1cd4_13.0.zip/download</link>
      <pubDate>Wed, 25 Nov 2026 23:52:32 UT</pubDate>
      <media:content url="https://sourceforge.net/projects/flickerdev/files/Firmware/thyme/fw_thyme_miui_THYME_OS1.0.4.0.TGACNXM_80dbab1cd4_13.0.zip/download" filesize="152005860"><media:hash algo="md5">40b214ab288395ed0823c3ce9d085268</media:hash></media:content>
    </item>
  </channel>
</rss>"#;

    #[test]
    fn parses_sourceforge_urls_and_encodes_paths() {
        let rom = Source::parse_url("https://sourceforge.net/projects/flickerdev/files/ROM/").unwrap();
        assert_eq!((rom.project.as_str(), rom.base_path.as_str()), ("flickerdev", "/ROM"));
        assert_eq!(rom.rss_url(&rom.base_path), "https://sourceforge.net/projects/flickerdev/rss?path=/ROM");
        let root = Source::parse_url("https://sourceforge.net/projects/flickerdev/files/").unwrap();
        assert_eq!(root.base_path, "/");
        assert_eq!(root.files_url("/"), "https://sourceforge.net/projects/flickerdev/files/");
        let fw = Source::parse_url("https://sourceforge.net/projects/flickerdev/files/Firmware/thyme").unwrap();
        assert_eq!(fw.base_path, "/Firmware/thyme");
        assert!(Source::parse_url("https://example.com/projects/flickerdev/files/").is_err());
    }

    #[test]
    fn filters_flashable_zips_by_device_and_sorts_newest_first() {
        let entries = parse_rss(SAMPLE_RSS).unwrap();
        let roms = packages(&entries, "/ROM", "thyme");
        assert_eq!(roms.len(), 2);
        assert_eq!(roms[0].release.version, "PixelOS_thyme-16.2-20260624-1725");
        assert_eq!(roms[0].channel, "sixteen / qpr2 / PixelOS / 20260625");
        assert_eq!(roms[0].release.md5, "f6b3e3cb34a5048166a3ac9dc2e25105");
        assert_eq!(roms[0].release.length, Some(2_611_868_200));
        assert_eq!(roms[1].release.version, "PixelOS_thyme-15.0-20250718-1351");
        assert_eq!(roms[1].channel, "fifteen / PixelOS / 20250718");

        let fw = packages(&entries, "/Firmware/thyme", "thyme");
        assert_eq!(fw.len(), 1);
        assert_eq!(fw[0].release.name, "fw_thyme_miui_THYME_OS1.0.4.0.TGACNXM_80dbab1cd4_13.0.zip");
        assert!(fw[0].channel.is_empty());
    }

    #[test]
    fn extracts_subfolders_from_html_listing() {
        let html = r#"
            <table>
                <tr title="sixteen" class="folder "></tr>
                <tr title="fifteen" class="folder "></tr>
                <tr title="PixelOS_thyme.zip" class="file "></tr>
                <tr title="{{name}}" class="folder "></tr>
            </table>
        "#;
        assert_eq!(parse_folders(html), ["sixteen", "fifteen"]);
    }
}
