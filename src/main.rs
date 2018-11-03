use std::vec::Vec;
use std::fs::File;
use std::io::Read;
use std::collections::HashSet;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;
use std::net::IpAddr;
use std::str::FromStr;
use std::borrow::Borrow;

extern crate rand;
extern crate chrono;
extern crate chrono_tz;
extern crate scrypt;
#[macro_use] extern crate rouille;
pub extern crate percent_encoding;
extern crate regex;
extern crate ipnet;
extern crate sha3;

use sha3::Digest;
use rand::Rng;
use chrono::TimeZone;
use regex::Regex;
use scrypt::{ScryptParams, scrypt_simple, scrypt_check};

fn unix_ms_to_string(unix_ms : u64) -> String
{
    chrono_tz::America::New_York.timestamp((unix_ms/1000) as i64, ((unix_ms%1000)*1000000) as u32).format("%Y-%m-%d %H:%M:%S %Z").to_string()
}

fn unix_ms_to_html_string(unix_ms : u64) -> String
{
    entity_escape(&unix_ms_to_string(unix_ms))
}

struct PostData {
    id: u64,
    thread: u64,
    name: String,
    text: String,
    ip: String,
    unix_ms: u64,
    edited_unix_mx: u64,
    show_isadmin: bool,
    show_ismod: bool,
}

enum SaltyEvent {
    Text(String),
    Insert{name:String, formatter:String}
}

fn parse_salty_template(template : &String) -> Vec<SaltyEvent>
{
    let re = Regex::new(&r#"((?s).*?)\{\{\{(.*?):(.*?)\}\}\}((?s).*)"#).unwrap();
    
    if let Some(caps) = re.captures(template)
    {
        let prefix = SaltyEvent::Text(caps.get(1).unwrap().as_str().to_string());
        let insert_name = caps.get(2).unwrap().as_str().to_string();
        let insert_type = caps.get(3).unwrap().as_str().to_string();
        let mut suffix = parse_salty_template(&caps.get(4).unwrap().as_str().to_string());
        
        let mut ret = Vec::<SaltyEvent>::new();
        ret.reserve(suffix.len()+2);
        ret.push(prefix);
        ret.push(SaltyEvent::Insert{name:insert_name, formatter:insert_type});
        ret.append(&mut suffix);
        
        ret
    }
    else
    {
        vec!(SaltyEvent::Text(template.clone()))
    }
}

fn salty_template(template : &String, inserts_vec : &Vec<(&'static str, String)>) -> Result<String, String>
{
    let seen_insert_events = HashSet::<String>::new();
    let events = parse_salty_template(template);
    
    let mut inserts = HashMap::<String, String>::new();
    
    for insert in inserts_vec
    {
        inserts.insert(insert.0.to_string(), insert.1.clone());
    }
    
    let mut ret = "".to_string();
    
    for event in events
    {
        match event
        {
            SaltyEvent::Text(text) =>
            {
                ret += &text;
            }
            SaltyEvent::Insert{name, formatter} =>
            {
                if let Some(insert_text) = inserts.get(&name)
                {
                    ret += &
                    match formatter.as_str()
                    {
                        "raw" => insert_text.clone(),
                        "percent" => url_escape(&insert_text),
                        "weak_percent" => full_url_escape(&insert_text),
                        "entities" => entity_escape(&insert_text),
                        "bbcode" => bbcode_to_html(insert_text, false),
                        "bbcode_post" => post_escape(insert_text),
                        "bbcode_admin" => bbcode_to_html(insert_text, true),
                        "digits_only" =>
                        {
                            for c in insert_text.chars()
                            {
                                if !c.is_ascii_digit()
                                {
                                    return Err("template contains insert of formatter `digits_only` but inserted text contains things other than ascii digits".to_string());
                                }
                            }
                            insert_text.clone()
                        }
                        "alphanum_only" =>
                        {
                            for c in insert_text.chars()
                            {
                                if !c.is_ascii_alphanumeric()
                                {
                                    return Err("template contains insert of formatter `alphanum_only` but inserted text contains things other than ascii alphanumerics".to_string());
                                }
                            }
                            insert_text.clone()
                        }
                        "alphanum_plus_only" =>
                        {
                            for c in insert_text.chars()
                            {
                                if !c.is_ascii_alphanumeric() && c != '=' && c != '_'
                                {
                                    return Err("template contains insert of formatter `alphanum_plus_only` but inserted text contains things other than ascii alphanumerics or [=_]".to_string());
                                }
                            }
                            insert_text.clone()
                        }
                        _ =>
                        {
                            return Err(format!("template contains unknown formatter `{}`", name));
                        }
                    };
                }
                else
                {
                    return Err(format!("template contains event `{}` that is not in the set of inserts", name));
                }
            }
        }
    }
    Ok(ret)
}

// tuple: type, name, placeholder, value
fn format_admin_action_field_button(arg_board : &str, action : &str, button_name : &str, fields : &[(&str, &str, &str, &str)]) -> String
{
    let board = 
        if arg_board == "" { "".to_string() }
        else { format!("/{}", &url_escape(&arg_board.to_string())) }
    ;
    let mut fields_html = "".to_string();
    for field in fields.iter()
    {
        let maybebr = 
            if field.0 == "hidden" {""}
            else {"<br>"}
        .to_string();
        
        fields_html += &salty_template(
            &"<input type=\"{{{type:entities}}}\" \
            name=\"{{{name:entities}}}\" \
            placeholder=\"{{{placeholder:entities}}}\" \
            value=\"{{{value:entities}}}\" \
            class=stackedforminput>\
            {{{maybebr:raw}}}\n".to_string(),
            &vec!(
             ("type", field.0.to_string()),
             ("name", field.1.to_string()),
             ("placeholder", field.2.to_string()),
             ("value", field.3.to_string()),
             ("maybebr", maybebr)
            )).unwrap();
    }
    
    return salty_template(
        &"<form method=POST enctype=\"multipart/form-data\" action=\"{{{board:raw}}}/admin/action/{{{action:alphanum_plus_only}}}\" class=inline>\n\
         {{{fields:raw}}}\
         <button type=submit>{{{buttonname:entities}}}</button>\n</form>\n".to_string(),
        &vec!(
         ("board", board),
         ("action", action.to_string()),
         ("fields", fields_html),
         ("buttonname", button_name.to_string()),
        )).unwrap();
}

fn filter_ip(ip : &String, is_global_admin : bool) -> String
{
    if is_global_admin
    {
        ip.clone()
    }
    else
    {
        if let Some(addr) = string_to_ip(ip)
        {
            match addr
            {
                IpAddr::V4(_) =>
                {
                    if let Ok(net) = ipnet::Ipv4Net::from_str(&[ip.clone(), "/24".to_string()].concat())
                    {
                        net.network().to_string()
                    }
                    else
                    {
                        "(error recovering IP)".to_string()
                    }
                }
                IpAddr::V6(_) =>
                {
                    if let Ok(net) = ipnet::Ipv6Net::from_str(&[ip.clone(), "/48".to_string()].concat())
                    {
                        net.network().to_string()
                    }
                    else
                    {
                        "(error recovering IP)".to_string()
                    }
                }
            }
        }
        else
        {
            "(error recovering IP)".to_string()
        }
    }
}

impl PostData {
    fn get_filtered_ip(&self, is_global_admin : bool) -> String
    {
        filter_ip(&self.ip, is_global_admin)
    }
    fn get_banrange(&self) -> Option<BanRange>
    {
        if let Some(addr) = string_to_ip(&self.ip)
        {
            match addr
            {
                IpAddr::V4(_) =>
                {
                    string_to_banrange(&[self.ip.clone(), "/32".to_string()].concat())
                }
                IpAddr::V6(_) =>
                {
                    string_to_banrange(&[self.ip.clone(), "/64".to_string()].concat()) // the last 64 bits of an ipv6 address is basically a client ID
                }
            }
        }
        else
        {
            None
        }
    }
    fn htmlify(&self, board : &BoardData, istopic : bool, isadmin : bool, ismod : bool) -> String
    {
        let mut edited = "".to_string();
        let mut postip = "".to_string();
        let mut deletebutton = "".to_string();
        let mut editbutton = "".to_string();
        let mut banbutton = "".to_string();
        
        let isadmin_html =
        if self.show_isadmin { "<span style=\"color:red\">Administrator</span>" }
        else if self.show_ismod { "<span style=\"color:green\">Moderator</span>" }
        else { "" }
        .to_string();
        
        if self.edited_unix_mx != 0
        {
            // entities
            edited = format!(" (edited by an admin/mod on {})", unix_ms_to_string(self.edited_unix_mx));
        }
        
        if isadmin | ismod
        {
            // entities
            if isadmin
            {
                postip = format!("\n ({})\n", &self.get_filtered_ip(true));
            }
            else
            {
                postip = format!("\n ({})\n", &self.get_filtered_ip(false));
            }
            // raw html
            deletebutton = format_admin_action_field_button(
                        &board.dir[..],
                        &"delete_post",
                        &"Delete",
                        &[(&"hidden", &"postnum", &"", &self.id.to_string().as_str())]);
            editbutton = format_admin_action_field_button(
                        &board.dir[..],
                        &"edit_post",
                        &"Edit",
                        &[(&"hidden", &"postnum", &"", &self.id.to_string().as_str())]);
            banbutton = format_admin_action_field_button(
                        &board.dir[..],
                        &"ban_post",
                        &"Ban",
                        &[(&"hidden", &"postnum", &"", &self.id.to_string().as_str())]);
        }
        
        let mut extrastyle = "".to_string();
        let mut topicheader = "".to_string();
        
        if istopic
        {
            extrastyle = "width: 100%".to_string();
            
            let title =
                if self.thread == board.current_thread { board.current_title.clone() }
                else {
                    if let Some((title, _)) = board.threads.get(&self.thread) { title.clone() }
                    else { "".to_string() }
                }
            ;
            topicheader = salty_template(
                &"<div class=topicheader>Thread <a href=\"/{{{boarddir:percent}}}/{{{thread:digits_only}}}\">#{{{thread:digits_only}}}</a> - {{{threadname:entities}}}</div>".to_string(),
                &vec!(
                 ("boarddir", board.dir.clone()),
                 ("thread", self.thread.to_string()),
                 ("threadname", title),
                )).unwrap();
        }
        
        salty_template(&"\
<div class=postwrapper style=\"{{{extracss:entities}}}\" id=\"{{{postid:digits_only}}}\">
 <div class=post>
  {{{topicheader:raw}}}
  <div class=postheader>
   <a href=\"/{{{boarddir:percent}}}/{{{thread:digits_only}}}#{{{postid:digits_only}}}\">No.</a>{{{postid:digits_only}}}
    - by {{{isadmin:raw}}} <span class=postname>{{{postername:entities}}}</span> on <span class=posttime>{{{time:entities}}}</span>
    {{{postip:entities}}}{{{deletebutton:raw}}}{{{editbutton:raw}}}{{{banbutton:raw}}}
    <br>{{{edited:entities}}}
  </div>
  <div class=postcontent>{{{posttext:bbcode_post}}}</div>
 </div>
</div>".to_string(),
        &vec!(
         ("extracss", extrastyle),
         ("postid", self.id.to_string()),
         ("boarddir", board.dir.clone()),
         ("thread", self.thread.to_string()),
         ("topicheader", topicheader),
         ("postername", self.name.clone()),
         ("time", unix_ms_to_string(self.unix_ms)),
         ("posttext", self.text.clone()),
         ("edited", edited),
         ("postip", postip),
         ("deletebutton", deletebutton),
         ("editbutton", editbutton),
         ("banbutton", banbutton),
         ("isadmin", isadmin_html),
        )).unwrap()
    }
}

#[derive(Clone)]
struct AdminData {
    name: String,
    passhash: String,
}


#[derive(Clone)]
#[derive(Debug)]
struct AdminSession {
    name: String,
    ip: String,
    session_id_hash: String,
    login_unix_ms: u64,
    last_reroll_unix_ms: u64,
    expires_unix_ms: u64,
    boardurl: String
}

fn random_base_62(n : usize) -> String
{
    rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(n).collect::<String>()
}

fn hash_string(s : &String) -> String
{
    format!("{:x}", sha3::Sha3_512::digest(s.as_bytes()))
}

impl AdminSession {
    fn new(name : String, ip : IpAddr, boardurl : String) -> AdminSession
    {
        AdminSession{name, ip : ip.to_string(), session_id_hash : "".to_string(), login_unix_ms : 0, last_reroll_unix_ms : 0, expires_unix_ms : 0, boardurl}
    }
    fn refresh_and_format_cookie_text(&mut self, old_session_id : &String) -> String
    {
        let now = get_unix_ms();
        // reroll the session ID every 15 minutes
        let cookiename =
        if self.boardurl == "" { "adminsession=".to_string() }
        else { format!("boardadminsession={}:", self.boardurl) };
        
        if old_session_id.as_str() == "" || now - self.last_reroll_unix_ms > 15*60*1000
        {
            let session_id = random_base_62(64);
            self.last_reroll_unix_ms = now;
            self.session_id_hash = hash_string(&session_id);
            self.expires_unix_ms = now + 60*60*1000;
            format!("{}{}; Max-Age={}; Path=/; HttpOnly; SameSite=Strict", &cookiename, &session_id, 60*60/*an hour*/)
        }
        else
        {
            self.expires_unix_ms = now + 60*60*1000;
            format!("{}{}; Max-Age={}; Path=/; HttpOnly; SameSite=Strict", &cookiename, old_session_id, 60*60/*an hour*/)
        }
    }
    fn is_global(&self) -> bool
    {
        if self.boardurl == "" { true } else { false }
    }
}

struct AdminLoginAttempt {
    name: String,
    ip: String,
    unix_ms: u64,
    success: bool
}

impl AdminLoginAttempt {
    fn new(name : &String, ip : &IpAddr, success : bool) -> AdminLoginAttempt
    {
        AdminLoginAttempt{ name : name.clone(), ip : ip.to_string(), unix_ms : get_unix_ms(), success }
    }
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq)]
#[derive(Ord)]
enum BanRange {
    V4 { prefix : u32, mask : u32, prefix_len : u8, unix_ms : u64 },
    V6 { prefix : u128, mask : u128, prefix_len : u8, unix_ms : u64 },
}

impl PartialEq for BanRange {
    fn eq(&self, other: &BanRange) -> bool {
        match self
        {
            BanRange::V4{prefix, mask, prefix_len : _, unix_ms : _ } =>
            {
                match other
                {
                    BanRange::V4{prefix : other_prefix, mask : other_mask, prefix_len : _, unix_ms : _ } =>
                    {
                        prefix == other_prefix && mask == other_mask
                    }
                    BanRange::V6{prefix : _, mask : _, prefix_len : _, unix_ms : _ } => false
                }
            }
            BanRange::V6{prefix, mask, prefix_len : _, unix_ms : _ } =>
            {
                match other
                {
                    BanRange::V6{prefix : other_prefix, mask : other_mask, prefix_len : _, unix_ms : _ } =>
                    {
                        prefix == other_prefix && mask == other_mask
                    }
                    BanRange::V4{prefix : _, mask : _, prefix_len : _, unix_ms : _ } => false
                }
            }
        }
    }
}

impl std::hash::Hash for BanRange {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self
        {
            BanRange::V4{prefix, mask, prefix_len : _, unix_ms : _ } =>
            {
                prefix.hash(state);
                mask.hash(state);
            }
            BanRange::V6{prefix, mask, prefix_len : _, unix_ms : _ } =>
            {
                prefix.hash(state);
                mask.hash(state);
            }
        }
    }
}

impl PartialOrd for BanRange {
    fn partial_cmp(&self, other : &BanRange) -> Option<std::cmp::Ordering> {
        match self
        {
            BanRange::V4{prefix : _, mask : _, prefix_len : _, unix_ms } |
            BanRange::V6{prefix : _, mask : _, prefix_len : _, unix_ms } =>
            {
                match other
                {
                    BanRange::V4{prefix : _, mask : _, prefix_len : _, unix_ms : other_unix_ms } |
                    BanRange::V6{prefix : _, mask : _, prefix_len : _, unix_ms : other_unix_ms } =>
                    {
                        Some(unix_ms.cmp(&other_unix_ms))
                    }
                }
            }
        }
    }
}

impl BanRange {
    fn to_string(&self, is_global_admin : bool) -> String
    {
        match self
        {
            BanRange::V4{prefix, mask : _, mut prefix_len, unix_ms : _} =>
            {
                let mut extend = "".to_string();
                if !is_global_admin && prefix_len > 24
                {
                    prefix_len = 24;
                    extend = " (truncated to /24)".to_string();
                }
                if let Ok(s) = ipnet::Ipv4Net::new(std::net::Ipv4Addr::from(*prefix), prefix_len)
                {
                    s.network().to_string() + "/" + &prefix_len.to_string() + &extend
                }
                else
                {
                    "".to_string()
                }
            }
            BanRange::V6{prefix, mask : _, mut prefix_len, unix_ms : _} =>
            {
                let mut extend = "".to_string();
                if !is_global_admin && prefix_len > 48
                {
                    prefix_len = 48;
                    extend = " (truncated to /48)".to_string();
                }
                if let Ok(s) = ipnet::Ipv6Net::new(std::net::Ipv6Addr::from(*prefix), prefix_len)
                {
                    s.network().to_string() + "/" + &prefix_len.to_string() + &extend
                }
                else
                {
                    "".to_string()
                }
            }
        }
    }
    fn is_match(&self, addr : &IpAddr) -> bool
    {
        if let IpAddr::V4(addr) = addr
        {
            if let BanRange::V4{prefix, mask, prefix_len : _, unix_ms : _} = self
            {
                *prefix == (u32::from(*addr) & *mask)
            }
            else
            {
                false
            }
        }
        else if let IpAddr::V6(addr) = addr
        {
            if let BanRange::V6{prefix, mask, prefix_len : _, unix_ms : _} = self
            {
                *prefix == (u128::from(*addr) & *mask)
            }
            else
            {
                false
            }
        }
        else
        {
            false
        }
    }
}

fn string_to_banrange(text : &String) -> Option<BanRange>
{
    if let Ok(net) = ipnet::Ipv4Net::from_str(text)
    {
        Some(BanRange::V4{prefix : u32::from(net.network()), mask : u32::from(net.netmask()), prefix_len : net.prefix_len(), unix_ms : get_unix_ms()})
    }
    else if let Ok(net) = ipnet::Ipv6Net::from_str(text)
    {
        Some(BanRange::V6{prefix : u128::from(net.network()), mask : u128::from(net.netmask()), prefix_len : net.prefix_len(), unix_ms : get_unix_ms()})
    }
    else
    {
        None
    }
}

fn string_to_ip(text : &String) -> Option<IpAddr>
{
    if let Ok(addr) = IpAddr::from_str(text)
    {
        Some(addr)
    }
    else
    {
        None
    }
}

struct BoardData {
    dir: String,
    name: String,
    
    salt: String,
    
    announcement_bbcode: String,
    
    threads: HashMap<u64, (String, HashSet<u64>)>,
    current_thread: u64,
    current_title: String,
    
    highest_post_id: u64,
    latest_time_per_ip: HashMap<String, u64>,
    posts: HashMap<u64, PostData>,
    seen_post_nonces: HashSet<String>,
    
    admins: HashMap<String, AdminData>,
    admin_sessions: HashMap<String, AdminSession>,
    admin_login_attempt_log: Vec<AdminLoginAttempt>,
    
    bans: HashMap<u64, BanRange>,
    highest_ban_id: u64,
    
    admin_action_log: Vec<(u64, String, String, String, String)> // time, name, board admin is associated with, ip, action
}

impl BoardData {
    fn new(boardurl : &String, boardtitle: &String) -> BoardData
    {
        BoardData{dir : boardurl.clone(), name : boardtitle.clone(), salt : random_base_62(32), announcement_bbcode : "".to_string(), threads : HashMap::new(), current_thread : 0, current_title : "Test Thread".to_string(), highest_post_id : 0, latest_time_per_ip : HashMap::new(), posts : HashMap::new(), seen_post_nonces : HashSet::new(), admins : HashMap::new(), admin_sessions : HashMap::new(), admin_login_attempt_log : Vec::new(), bans : HashMap::new(), highest_ban_id: 0, admin_action_log: Vec::new() }
    }
    fn htmlify(&self) -> String
    {
        salty_template(&"<a href=\"/{{{boarddir:percent}}}\">{{{boarddir:entities}}}</a> - {{{boardname:entities}}}".to_string(),
            &vec!(
             ("boarddir", self.dir.clone()),
             ("boardname", self.name.clone())
            )).unwrap()
    }
    fn refresh_board_admin_session(&mut self, mut session : AdminSession, response : &mut rouille::Response, old_session_id : &String)
    {
        let cookietext = session.refresh_and_format_cookie_text(old_session_id);
        self.admin_sessions.insert(session.session_id_hash.clone(), session);
        
        response.headers.push(("Set-Cookie".into(), cookietext.into()));
    }
}

struct ServerData {
    template: String,
    
    boards: HashMap<String, BoardData>,
    
    admins: HashMap<String, AdminData>,
    admin_sessions: HashMap<String, AdminSession>,
    
    hasher_config: ScryptParams,
    
    admin_login_attempt_log: Vec<AdminLoginAttempt>,
    
    name_bbcode: String,
    announcement_bbcode: String,
    
    bans: HashMap<u64, BanRange>,
    highest_ban_id: u64,
    
    admin_action_log: Vec<(u64, String, String, String)> // time, name, ip, action
}

fn url_escape(text : &String) -> String
{
    percent_encoding::utf8_percent_encode(text, percent_encoding::PATH_SEGMENT_ENCODE_SET).to_string()
}

fn full_url_escape(text : &String) -> String
{
    percent_encoding::utf8_percent_encode(text, percent_encoding::QUERY_ENCODE_SET).to_string()
}

fn entity_escape(text : &String) -> String
{
    let mut ret = text.clone();
    ret = ret.replace("&", "&amp;");
    ret = ret.replace(">", "&gt;");
    ret = ret.replace("<", "&lt;");
    ret = ret.replace("\"", "&quot;");
    ret = ret.replace("'", "&#x27;");
    ret = ret.replace("/", "&#x2F;");
    ret
}

fn post_escape(text : &String) -> String
{
    bbcode_to_html(&text.replace("\r", "").replace("\n", "[br]"), false)
}

/*
bbcode-like formatting:

[url]http://kanji.wareya.moe/[/url]
[url=http://kanji.wareya.moe/]kanji search[/url] (admin only)
[url="http://kanji.wareya.moe/"]kanji search[/url] (admin only)
[url="http://kanji.wareya.moe/\\\""]kanji search[/url] (admin only) (`...moe/\"`)
[ruby]絶対[r]ぜったい[/r]領域[r]りょういき[/r][/ruby]
[b]bold[/b]
[i]italic[/i]
[u]underline[/u]
[h]highlight[/h]
> greentext (from start of line only)

*/

impl ServerData {
    fn hash_password(&self, text : &String) -> Result<String, &str>
    {
        if text.bytes().count() > 2048
        {
            Err("password too long (2048 character limit) (wtf dude)")
        }
        else
        {
            match scrypt_simple(text, &self.hasher_config)
            {
                Ok(hash) => Ok(hash),
                _ => Err("server's RNG failed, try again later")
            }
        }
    }

    fn password_matches_hash(&self, password : &String, hash : &String) -> bool
    {
        match scrypt_check(password, hash)
        {
            Ok(()) => true,
            _ => false
        }
    }

    fn finish_generation_generic(&self, pagecontent : String, intraheaderbbcode : String) -> rouille::Response
    {
        self.finish_generation_with_postheader_bbcode(pagecontent, intraheaderbbcode, "".to_string())
    }
    fn finish_generation_with_postheader_bbcode(&self, pagecontent : String, intraheaderbbcode : String, postheaderbbcode : String) -> rouille::Response
    {
        // TODO move inner html to global server state
        let header = salty_template(
            &"<h1 class=notice>{{{sitename:bbcode_admin}}}</h1>\n\
              <h2 class=notice>{{{intraheaderbbcode:bbcode_admin}}}</h2>\n\
              <p class=notice>{{{siteannouncement:bbcode_admin}}}</p>\n\
              <p class=notice>{{{postheaderbbcode:bbcode_admin}}}</p>\n".to_string(),
            &vec!(
             ("sitename",self.name_bbcode.clone()),
             ("intraheaderbbcode",intraheaderbbcode),
             ("siteannouncement",self.announcement_bbcode.clone()),
             ("postheaderbbcode",postheaderbbcode),
            )).unwrap();
        
        let mut output = self.template.clone();
        output = output.replace("{{{header}}}", &header);
        output = output.replace("{{{pagecontent}}}", &pagecontent);
        rouille::Response::html(output)
    }
    fn finish_generation_with_board_title(&self, boardurl : &String, pagecontent : String) -> rouille::Response
    {
        // TODO move inner html to global server state
        if let Some(board) = self.boards.get(boardurl)
        {
            let intraheaderbbcode = format!("[badurl=\"{0}\"]#{0}[/badurl] - {1}", boardurl, board.name);
            self.finish_generation_with_postheader_bbcode(pagecontent, intraheaderbbcode, board.announcement_bbcode.clone())
        }
        else
        {
            self.finish_generation_generic(pagecontent, "(failed to get board info)".to_string())
        }
    }
    fn directory_text(&self) -> String
    {
        let mut pagecontent = "".to_string();
        
        let mut keys = self.boards.keys().cloned().collect::<Vec<String>>();
        keys.sort_unstable();
        
        for key in keys
        {
            if let Some(board) = self.boards.get(&key)
            {
                pagecontent += &board.htmlify();
                pagecontent += "<br>\n";
            }
            else
            {
                panic!("this should be unreachable!");
            }
        }
        
        pagecontent
    }
    fn board_text_no_post_form(&self, boardurl : &String, isadmin : bool, ismod : bool) -> String
    {
        if let Some(board) = self.boards.get(boardurl)
        {
            if board.threads.len() > 0
            {
                match self.board_thread_html(board, board.current_thread, isadmin, ismod)
                {
                    Ok(pagecontent) =>
                        pagecontent,
                    Err(_) =>
                        format!("failed to find current thread {}", board.current_thread)
                }
            }
            else
            {
                "There's nothing here yet! Make a new thread?".to_string()
            }
        }
        else
        {
            format!("no such board {}", entity_escape(boardurl))
        }
    }
    fn directory_default(&self) -> rouille::Response
    {
        self.finish_generation_generic(self.directory_text(), "Board Index".to_string())
    }
    fn board_frontpage(&self, boardurl : &String, isadmin : bool, ismod : bool) -> rouille::Response
    {
        self.finish_generation_with_board_title(boardurl, self.board_text_no_post_form(boardurl, isadmin, ismod) + &self.default_post_form(boardurl, isadmin, ismod))
    }
    fn board_archive(&self, boardurl : &String) -> rouille::Response
    {
        if let Some(board) = self.boards.get(boardurl)
        {
            let mut pagecontent = "<p class=\"notice\">Archive of past threads</p>".to_string();
            
            let mut thread_ids = board.threads.keys().cloned().collect::<Vec<u64>>();
            thread_ids.sort_unstable();
            
            for thread_id in thread_ids
            {
                let mut found_thread = false;
                if let Some((thread_title, posts)) = board.threads.get(&thread_id)
                {
                    let mut post_ids = posts.iter().cloned().collect::<Vec<u64>>();
                    post_ids.sort_unstable();
                    
                    if let Some(op_id) = post_ids.first()
                    {
                        if let Some(first_post) = board.posts.get(&op_id)
                        {
                            found_thread = true;
                            pagecontent += &format!("<p>Thread <a href=\"/{0}/{1}\">#{1} - {2}</a> - {3}</p>\n", url_escape(&boardurl), thread_id, entity_escape(&thread_title), unix_ms_to_html_string(first_post.unix_ms));
                        }
                    }
                }
                if !found_thread
                {
                    pagecontent += &format!("<p>(Failed to find thread {}</p>\n", thread_id);
                }
            }
            
            self.finish_generation_with_board_title(boardurl, pagecontent)
        }
        else
        {
            self.directory_default()
        }
    }
    // FIXME don't show post form if on archived thread
    fn board_with_error(&self, boardurl : &String, errormessage : &String, isadmin : bool, ismod : bool) -> rouille::Response
    {
        // TODO: migrate to template
        let pagecontent = format!("\n<div class=msgouter><div class=msginner>Error: {}</div></div>", entity_escape(&errormessage)) + &self.board_text_no_post_form(boardurl, isadmin, ismod) + &self.default_post_form(boardurl, isadmin, ismod);
        self.finish_generation_with_board_title(boardurl, pagecontent)
    }
    fn board_with_error_and_prefill(&self, boardurl : &String, errormessage : &String, name : &String, text : &String, title : &String, isadmin : bool, ismod : bool) -> rouille::Response
    {
        // TODO: migrate to template
        let pagecontent = format!("\n<div class=msgouter><div class=msginner>Error: {}</div></div>", entity_escape(&errormessage)) + &self.board_text_no_post_form(boardurl, isadmin, ismod) + &self.prefill_post_form(boardurl, name, text, title, isadmin, ismod);
        self.finish_generation_with_board_title(boardurl, pagecontent)
    }
    fn search(&self, boardurl : &String, thread_id : u64, isadmin : bool, ismod : bool) -> rouille::Response
    {
        if let Some(board) = self.boards.get(boardurl)
        {
            self.board_display_thread(board, thread_id, isadmin, ismod)
        }
        else
        {
            self.directory_default()
        }
    }
    fn board_thread_html(&self, board : &BoardData, thread_id : u64, isadmin : bool, ismod : bool) -> Result<String, String>
    {
        if let Some((_thread_title, posts)) = board.threads.get(&thread_id)
        {
            let mut pagecontent = "".to_string();
            
            // TODO: migrate to template
            
            pagecontent += &format!("<p class=notice><a href=\"/{}/archive\">Archive</a></p>", url_escape(&board.dir));
            
            let mut istopic = true;
            
            let mut post_ids = posts.iter().cloned().collect::<Vec<u64>>();
            post_ids.sort_unstable();
            
            for post_id in post_ids
            {
                if let Some(post) = board.posts.get(&post_id)
                {
                    pagecontent += &post.htmlify(&board, istopic, isadmin, ismod);
                    pagecontent += "\n";
                }
                istopic = false;
            }
            
            Ok(pagecontent)
        }
        else
        {
            Err(format!("no such thread {}, displaying front page", thread_id))
        }
    }
    fn board_display_thread(&self, board : &BoardData, thread_id : u64, isadmin : bool, ismod : bool) -> rouille::Response
    {
        match self.board_thread_html(board, thread_id, isadmin, ismod)
        {
            Ok(pagecontent) =>
                self.finish_generation_with_board_title(&board.dir, pagecontent + &self.default_post_form(&board.dir, isadmin, ismod)),
            Err(errcontent) =>
                self.board_with_error(&board.dir, &errcontent, isadmin, ismod),
        }
    }
    fn get_admin_session_from_string(&self, remote_ip : &IpAddr, session_string : &String) -> Option<AdminSession>
    {
        if let Some(session) = self.admin_sessions.get(&hash_string(session_string))
        {
            if get_unix_ms() < session.expires_unix_ms && remote_ip.to_string() == session.ip
            {
                return Some(session.clone());
            }
        }
        return None;
    }
    fn get_board_admin_session_from_string(&self, boardurl : &String, remote_ip : &IpAddr, session_string : &String) -> Option<AdminSession>
    {
        if let Some(board) = self.boards.get(boardurl)
        {
            if let Some(session) = board.admin_sessions.get(&hash_string(session_string))
            {
                if get_unix_ms() < session.expires_unix_ms && remote_ip.to_string() == session.ip
                {
                    return Some(session.clone());
                }
            }
        }
        return None;
    }
    fn refresh_admin_session(&mut self, mut session : AdminSession, response : &mut rouille::Response, old_session_id : &String)
    {
        let cookietext = session.refresh_and_format_cookie_text(old_session_id);
        self.admin_sessions.insert(session.session_id_hash.clone(), session);
        
        response.headers.push(("Set-Cookie".into(), cookietext.into()));
    }
    fn make_message_safe(&self, text : &String) -> String
    {
        format!("<div class=msgouter><div class=msginner>{}</div></div>", entity_escape(text))
    }
    fn generate_admin_page_for_session(&mut self, session : AdminSession) -> rouille::Response
    {
        let greeting = self.make_message_safe(&format!("You are logged in as administrator \"{}\".\n", &session.name));
        
        // admin table
        
        let mut admin_login_log_table = "".to_string();
        admin_login_log_table += &"<div><p>Admin Login Attempt Event Log</p>\n<p><table>\n<thead><tr><th>username</th><th>ip_address</th><th>time</th><th>success</th></tr></thead>\n<tbody>\n";
        for event in &self.admin_login_attempt_log
        {
            admin_login_log_table += &salty_template(
                &"<tr><td>{{{name:entities}}}</td><td>{{{ip:entities}}}</td><td>{{{time:entities}}}</td><td>{{{success:raw}}}</td></tr>".to_string(),
                &vec!(
                 ("name", event.name.clone()),
                 ("ip", event.ip.clone()),
                 ("time", unix_ms_to_string(event.unix_ms)),
                 ("success", if event.success { "<b>yes</b>" } else { "no" }.to_string())
                )).unwrap();
        }
        admin_login_log_table += &"</tbody>\n</table></p>\n</div>\n";
        
        // board/post table
        
        let mut board_list_table = "".to_string();
        
        board_list_table += &"<div><p>Board listing</p>\n<p><table>\n<thead><tr><th>board url</th><th>board name</th><th>number of threads</th><th>number of posts</th></tr></thead>\n<tbody>\n";
        
        let mut board_urls = self.boards.keys().cloned().collect::<Vec<String>>();
        board_urls.sort_unstable();
        for boardurl in board_urls
        {
            if let Some(board) = self.boards.get(&boardurl)
            {
                board_list_table += &salty_template(
                    &"<tr><td>{{{dir:entities}}}</td><td>{{{name:entities}}}</td><td>{{{threads:digits_only}}}</td><td>{{{posts:digits_only}}}</td></tr>".to_string(),
                    &vec!(
                     ("dir", board.dir.clone()),
                     ("name", board.name.clone()),
                     ("threads", board.threads.len().to_string()),
                     ("posts", board.posts.len().to_string())
                    )).unwrap();
            }
        }
        board_list_table += &"</tbody>\n</table></p>\n</div>\n";
        
        // ban listing table
        
        let mut ban_list_table = "".to_string();
        
        ban_list_table += &"<div><p>Ban listing</p>\n<p><table>\n<thead><tr><th>ip mask</th><th>unban</th></tr></thead>\n<tbody>\n";
        
        let mut bans = self.bans.iter().map(|x| (*x.0, x.1.clone())).collect::<Vec<(u64, BanRange)>>();
        bans.sort_unstable();
        for (banid, ban) in bans
        {
            let button_html = format_admin_action_field_button(
                &"", // no board
                &"remove_ban",
                &"Remove",
                &[("hidden", "ban_id", "", banid.to_string().as_str())]);
            
            ban_list_table += &salty_template(
                &"<tr><td>{{{ban:entities}}}</td><td>{{{button:raw}}}</td></tr>".to_string(),
                &vec!(
                 ("ban", ban.to_string(session.is_global())),
                 ("button", button_html),
                )).unwrap();
        }
        ban_list_table += &"</tbody>\n</table></p>\n</div>\n";
        
        // action listing
        
        let mut action_list = "".to_string();
        
        action_list += &format!("<p>{}</p>\n", 
            &format_admin_action_field_button(
                &"", // no board
                &"create_board",
                &"Create new board",
                &[("text", "url", "url", ""), ("text", "name", "name", "")]));
        
        action_list += &format!("<p>{}</p>\n", 
            &format_admin_action_field_button(
                &"", // no board
                &"change_site_name",
                &"Change site name",
                &[("text", "bbcode", "name (bbcode)", "")]));
        
        action_list += &format!("<p>{}</p>\n", 
            &format_admin_action_field_button(
                &"", // no board
                &"change_site_announcement",
                &"Change site announcement",
                &[("text", "bbcode", "announcement (bbcode)", "")]));
        
        action_list += &format!("<p>{}</p><p class=infotext>Bans are specified with subnets. Subnets typically look like \"198.51.100.0/24\" (all IPs matching 198.51.100.*) or \"198.51.0.0/16\" (all IPs matching 198.51.*.*). See also https://en.wikipedia.org/wiki/Subnetwork</p>\n", 
            &format_admin_action_field_button(
                &"", // no board
                &"add_ban",
                &"Add ban",
                &[("text", "mask", "subnet", "")]));
        
        // TODO: migrate to template
        
        let mut pagehtml = "".to_string();
        pagehtml += &greeting;
        pagehtml += &admin_login_log_table;
        pagehtml += &board_list_table;
        pagehtml += &ban_list_table;
        pagehtml += &action_list;
        
        self.finish_generation_generic(pagehtml, "Administration".to_string())
    }
    fn generate_board_admin_page_for_session(&mut self, boardurl : &String, session : AdminSession) -> rouille::Response
    {
        if let Some(board) = self.boards.get(boardurl)
        {
            let greeting = self.make_message_safe(&format!("You are logged in as administrator \"{}\" on board #{}.\n", &session.name, boardurl));
            
            // admin table
            
            let mut admin_login_log_table = "".to_string();
            admin_login_log_table += &"<div><p>Moderator Login Attempt Event Log</p>\n<p><table>\n<thead><tr><th>username</th><th>ip_address</th><th>time</th><th>success</th></tr></thead>\n<tbody>\n";
            for event in &board.admin_login_attempt_log
            {
                admin_login_log_table += &salty_template(
                    &"<tr><td>{{{name:entities}}}</td><td>{{{ip:entities}}}</td><td>{{{time:entities}}}</td><td>{{{success:raw}}}</td></tr>".to_string(),
                    &vec!(
                     ("name", event.name.clone()),
                     ("ip", event.ip.clone()),
                     ("time", unix_ms_to_string(event.unix_ms)),
                     ("success", if event.success { "<b>yes</b>" } else { "no" }.to_string())
                    )).unwrap();
            }
            admin_login_log_table += &"</tbody>\n</table></p>\n</div>\n";
            
            // post table
            
            let mut post_list_table = "".to_string();
            
            post_list_table += &"<div><p>Post listing</p>\n<p><table>\n<thead><tr><th>id</th><th>thread id</th><th>name</th><th>text (bbcode)</th><th>ip address</th><th>time posted</th><th>time edited</th><th>by admin</th><th>by moderator</th></tr></thead>\n<tbody>\n";
            
            let mut post_ids = board.posts.keys().cloned().collect::<Vec<u64>>();
            post_ids.sort_unstable();
            
            for post_id in &post_ids
            {
                let post = board.posts.get(post_id).unwrap();
                post_list_table += &salty_template(
                    &"<tr><td>{{{id:digits_only}}}</td><td>{{{thread:digits_only}}}</td><td>{{{name:entities}}}</td><td>{{{text:entities}}}</td><td>{{{ip:entities}}}</td><td>{{{time:entities}}}</td><td>{{{timeedited:entities}}}</td><td>{{{byadmin:raw}}}</td><td>{{{bymod:raw}}}</td><td>{{{name:entities}}}</td></tr>".to_string(),
                    &vec!(
                     ("id", post.id.to_string()),
                     ("thread", post.thread.to_string()),
                     ("name", post.name.clone()),
                     ("text", post.text.clone()),
                     ("ip", post.get_filtered_ip(session.is_global())),
                     ("time", unix_ms_to_string(post.unix_ms)),
                     ("timeedited", unix_ms_to_string(post.unix_ms)),
                     ("byadmin", if post.show_isadmin {"<b>yes</b>"} else {"no"}.to_string()),
                     ("bymod", if post.show_ismod {"<b>yes</b>"} else {"no"}.to_string()),
                    )).unwrap();
            }
            post_list_table += &"</tbody>\n</table></p>\n</div>\n";
            
            // ban listing table
            
            let mut ban_list_table = "".to_string();
            
            ban_list_table += &"<div><p>Ban listing</p>\n<p><table>\n<thead><tr><th>ip mask</th><th>unban</th></tr></thead>\n<tbody>\n";
            
            let mut bans = board.bans.iter().map(|x| (*x.0, x.1.clone())).collect::<Vec<(u64, BanRange)>>();
            bans.sort_unstable();
            for (banid, ban) in bans
            {
                let button_html = format_admin_action_field_button(
                    &boardurl[..],
                    &"remove_ban",
                    &"Remove",
                    &[("hidden", "ban_id", "", banid.to_string().as_str())]);
                
                ban_list_table += &salty_template(
                    &"<tr><td>{{{ban:entities}}}</td><td>{{{button:raw}}}</td></tr>".to_string(),
                    &vec!(
                     ("ban", ban.to_string(session.is_global())),
                     ("button", button_html),
                    )).unwrap();
            }
            ban_list_table += &"</tbody>\n</table></p>\n</div>\n";
            
            // action listing
            
            let mut action_list = "".to_string();
            
            action_list += &format!("<p>{}</p>\n", 
                &format_admin_action_field_button(
                    &boardurl[..],
                    &"change_board_announcement",
                    &"Change board announcement",
                    &[("text", "bbcode", "announcement (bbcode)", "")]));
            
            action_list += &format!("<p>{}</p><p class=infotext>Bans are specified with subnets. Subnets typically look like \"198.51.100.0/24\" (all IPs matching 198.51.100.*) or \"198.51.0.0/16\" (all IPs matching 198.51.*.*). See also https://en.wikipedia.org/wiki/Subnetwork</p>\n", 
                &format_admin_action_field_button(
                    &boardurl[..],
                    &"add_ban",
                    &"Add ban",
                    &[("text", "mask", "subnet", "")]));
            
            // TODO: migrate to template
            
            let mut pagehtml = "".to_string();
            pagehtml += &greeting;
            pagehtml += &admin_login_log_table;
            pagehtml += &post_list_table;
            pagehtml += &ban_list_table;
            pagehtml += &action_list;
            
            self.finish_generation_generic(pagehtml, "Administration".to_string())
        }
        else
        {
            let greeting = self.make_message_safe(&format!("Internal error: you have an administrator session for board #{} but no such board exists.\n", boardurl));
            self.finish_generation_generic(greeting, "Administration".to_string())
        }
    }
    fn get_admin_login_form(&self) -> String
    {
        format_admin_action_field_button(
            &"",
            &"login",
            &"Log In",
            &[("text", "username", "username", ""),
              ("password", "password", "password", "")])
    }
    fn get_board_admin_login_form(&self, boardurl : &String) -> String
    {
        format_admin_action_field_button(
            &boardurl[..],
            &"login",
            &"Log In",
            &[("text", "username", "username", ""),
              ("password", "password", "password", "")])
    }
    fn generate_admin_login_page(&self) -> rouille::Response
    {
        let form = self.get_admin_login_form();
        self.finish_generation_generic(form, "Admin Login".to_string())
    }
    fn generate_board_admin_login_page(&self, boardurl : &String) -> rouille::Response
    {
        let form = self.get_board_admin_login_form(boardurl);
        self.finish_generation_generic(form, "Admin Login".to_string())
    }
    fn attempt_admin_login(&mut self, name : &String, password : &String, ip : &IpAddr) -> rouille::Response
    {
        if let Some(account) = self.admins.get(name).cloned()
        {
            if self.password_matches_hash(password, &account.passhash)
            {
                let mut newsession = AdminSession::new(name.clone(), ip.clone(), "".to_string());
                
                self.admin_login_attempt_log.push(AdminLoginAttempt::new(name, ip, true));
                
                let mut response = rouille::Response::redirect_302("/admin");
                self.refresh_admin_session(newsession, &mut response, &"".to_string());
                return response;
            }
        }
        self.admin_login_attempt_log.push(AdminLoginAttempt::new(name, ip, false));
        return rouille::Response::redirect_302("/admin");
    }
    fn attempt_board_admin_login(&mut self, boardurl : &String, name : &String, password : &String, ip : &IpAddr) -> rouille::Response
    {
        let adminpageurl = format!("/{}/admin", boardurl);
        if self.boards.contains_key(boardurl)
        {
            if let Some(account) = self.boards.get(boardurl).unwrap().admins.get(name).cloned()
            {
                if self.password_matches_hash(password, &account.passhash)
                {
                    if let Some(board) = self.boards.get_mut(boardurl)
                    {
                        let mut newsession = AdminSession::new(name.clone(), ip.clone(), boardurl.clone());
                        
                        board.admin_login_attempt_log.push(AdminLoginAttempt::new(name, ip, true));
                        
                        let mut response = rouille::Response::redirect_302(adminpageurl);
                        board.refresh_board_admin_session(newsession, &mut response, &"".to_string());
                        return response;
                    }
                }
            }
        }
        self.admin_login_attempt_log.push(AdminLoginAttempt::new(name, ip, false));
        return rouille::Response::redirect_302(adminpageurl);
    }
    fn attempt_admin_action(&mut self, session : &Option<AdminSession>, action : &String, ip : &IpAddr, request : &rouille::Request) -> rouille::Response
    {
        if action != "login" && session.is_none()
        {
            return rouille::Response::redirect_302("/admin");
        }
        
        if action == "login"
        {
            let data = try_or_400!(post_input!(request, {
                username: String,
                password: String,
            }));
            return self.attempt_admin_login(&data.username, &data.password, ip);
        }
        
        let session = session.as_ref().unwrap();
        
        macro_rules! add_to_log
        {
            ($string:expr) =>
            {
                self.admin_action_log.push((get_unix_ms(), session.name.clone(), session.ip.clone(), $string));
            }
        };
        
        match action.as_str()
        {
            "create_board" =>
            {
                let data = try_or_400!(post_input!(request, {
                    url: String,
                    name: String,
                }));
                if self.make_new_board(&data.url, &data.name).is_some()
                {
                    add_to_log!(format!("create_board `{:?}`", &data));
                }
                rouille::Response::redirect_302("/admin")
            }
            "change_site_name" =>
            {
                let data = try_or_400!(post_input!(request, {
                    bbcode: String,
                }));
                add_to_log!(format!("change_site_name `{}`", &data.bbcode));
                self.name_bbcode = data.bbcode;
                rouille::Response::redirect_302("/admin")
            }
            "change_site_announcement" =>
            {
                let data = try_or_400!(post_input!(request, {
                    bbcode: String,
                }));
                add_to_log!(format!("change_site_announcement `{}`", &data.bbcode));
                self.announcement_bbcode = data.bbcode;
                rouille::Response::redirect_302("/admin")
            }
            "add_ban" =>
            {
                let data = try_or_400!(post_input!(request, {
                    mask: String,
                }));
                if let Some(banrange) = string_to_banrange(&data.mask)
                {
                    add_to_log!(format!("add_ban `{}`", &data.mask));
                    self.bans.insert(self.highest_ban_id, banrange);
                    self.highest_ban_id += 1;
                }
                rouille::Response::redirect_302("/admin")
            }
            "remove_ban" =>
            {
                let data = try_or_400!(post_input!(request, {
                    ban_id: u64,
                }));
                add_to_log!(format!("remove_ban `{}`", &data.ban_id));
                self.bans.remove(&data.ban_id);
                rouille::Response::redirect_302("/admin")
            }
            _ =>
            {
                rouille::Response::redirect_302("/admin")
            }
        }
    }
    fn attempt_board_admin_action(&mut self, session : &Option<AdminSession>, boardurl : &String, action : &String, ip : &IpAddr, request : &rouille::Request) -> rouille::Response
    {
        let mut default_response =
        if self.boards.contains_key(boardurl)
        {
            rouille::Response::redirect_302(format!("/{}", url_escape(boardurl)))
        }
        else
        {
            rouille::Response::redirect_302("/")
        };
        
        if action != "login" && session.is_none()
        {
            return default_response;
        }
        
        if action == "login"
        {
            let data = try_or_400!(post_input!(request, {
                username: String,
                password: String,
            }));
            return self.attempt_board_admin_login(boardurl, &data.username, &data.password, ip);
        }
        
        if let Some(board) = self.boards.get(boardurl)
        {
            match action.as_str()
            {
                "edit_post" =>
                {
                    let data = try_or_400!(post_input!(request, {
                        postnum: String,
                    }));
                    
                    if let Ok(postnum) = data.postnum.parse::<u64>()
                    {
                        if let Some(post) = board.posts.get(&postnum)
                        {
                            return self.generate_post_edit_page(boardurl, &post.name, &post.text, &post.id);
                        }
                    }
                }
                _ => {}
            }
        }
        
        let session = session.as_ref().unwrap();
        
        if let Some(board) = self.boards.get_mut(boardurl)
        {
            macro_rules! add_to_log
            {
                ($string:expr) =>
                {
                    board.admin_action_log.push((get_unix_ms(), session.name.clone(), session.boardurl.clone(), session.ip.clone(), $string));
                }
            };
            match action.as_str()
            {
                "ban_post" =>
                {
                    let data = try_or_400!(post_input!(request, {
                        postnum: String,
                    }));
                    
                    if let Ok(postnum) = data.postnum.parse::<u64>()
                    {
                        if let Some(post) = board.posts.get(&postnum)
                        {
                            if let Some(banrange) = post.get_banrange()
                            {
                                add_to_log!(format!("ban_post `{}` `{}` `{}`", postnum, board.highest_ban_id, post.get_filtered_ip(session.is_global())));
                                board.highest_ban_id += 1;
                                board.bans.insert(board.highest_ban_id, banrange);
                            }
                        }
                    }
                }
                "delete_post" =>
                {
                    let data = try_or_400!(post_input!(request, {
                        postnum: String,
                    }));
                    
                    if let Ok(postnum) = data.postnum.parse::<u64>()
                    {
                        if let Some(post) = board.posts.remove(&postnum)
                        {
                            let parent_thread_id = post.thread;
                            if let Some((_thread_name, posts)) = board.threads.get_mut(&parent_thread_id)
                            {
                                if posts.contains(&postnum)
                                {
                                    add_to_log!(format!("delete_post `{}`", postnum));
                                    // FIXME: remove thread from board if it's empty
                                    posts.remove(&postnum);
                                    // FIXME: redirect to thread
                                }
                            }
                        }
                    }
                }
                "edit_post_submit" =>
                {
                    let data = try_or_400!(post_input!(request, {
                        username: String,
                        content: String,
                        postnum: String,
                    }));
                    
                    if let Ok(postnum) = data.postnum.parse::<u64>()
                    {
                        if let Some(post) = board.posts.get_mut(&postnum)
                        {
                            add_to_log!(format!("edit_post_submit `{}` `{}` `{}`", data.postnum, data.username, data.content));
                            
                            post.name = data.username;
                            post.text = data.content;
                            post.edited_unix_mx = get_unix_ms();
                            
                            // FIXME: admin-visible edit history
                            // FIXME: redirect to thread
                        }
                    }
                }
                "add_ban" =>
                {
                    default_response = rouille::Response::redirect_302(format!("/{}/admin", url_escape(boardurl)));
                    
                    let data = try_or_400!(post_input!(request, {
                        mask: String,
                    }));
                    if let Some(banrange) = string_to_banrange(&data.mask)
                    {
                        add_to_log!(format!("add_ban `{}`", data.mask));
                        board.highest_ban_id += 1;
                        board.bans.insert(board.highest_ban_id, banrange);
                    }
                }
                "remove_ban" =>
                {
                    default_response = rouille::Response::redirect_302(format!("/{}/admin", url_escape(boardurl)));
                    
                    let data = try_or_400!(post_input!(request, {
                        ban_id: u64,
                    }));
                    add_to_log!(format!("remove_ban `{}`", data.ban_id));
                    board.bans.remove(&data.ban_id);
                }
                "change_board_announcement" =>
                {
                    default_response = rouille::Response::redirect_302(format!("/{}/admin", url_escape(boardurl)));
                    
                    let data = try_or_400!(post_input!(request, {
                        bbcode: String,
                    }));
                    add_to_log!(format!("change_board_announcement `{}`", data.bbcode));
                    board.announcement_bbcode = data.bbcode;
                }
                _ => {}
            }
        }
        return default_response;
    }
    fn generate_post_edit_page(&self, boardurl : &String, post_name : &String, post_text : &String, post_number : &u64) -> rouille::Response
    {
        let form = salty_template(
            &"<form action=\"/{{{boarddir:percent}}}/admin/action/edit_post_submit\" method=\"POST\" enctype=\"multipart/form-data\">\n\
            <input value=\"{{{name:entities}}}\" placeholder=\"Anonymous\" type=\"text\" name=\"username\"> <button>Post</button><br>\n\
            <textarea name=\"content\" maxlength=\"5000\" style=\"width:500px; height:200px\">{{{text:entities}}}</textarea>\n\
            <input value=\"{{{postnum:digits_only}}}\" type=\"hidden\" name=\"postnum\">
            </form>".to_string(),
            &vec!(
             ("boarddir", boardurl.clone()),
             ("name", post_name.clone()),
             ("text", post_text.clone()),
             ("postnum", post_number.to_string())
            )).unwrap();
        self.finish_generation_with_board_title(&boardurl.to_string(), form)
    }
    fn make_new_board(&mut self, boardurl : &String, boardtitle : &String) -> Option<String> // Some on error, None on success
    {
        if boardurl.trim().len() == 0
        {
            Some(format!("tried to name a board with a blank url"))
        }
        else if boardtitle.trim().len() == 0
        {
            Some(format!("tried to name a board with a blank title"))
        }
        else if self.boards.contains_key(boardurl)
        {
            Some(format!("there is already a board named \"{}\"", boardurl))
        }
        else
        {
            self.boards.insert(boardurl.clone(), BoardData::new(boardurl, boardtitle));
            None
        }
    }
    fn insert_new_post(&mut self, boardurl : &String, name : &String, text : &String, ip : &IpAddr, nonce : &String, arg_title : &String, isadmin : bool, ismod : bool, show_isadmin : bool) -> Option<String>
    {  
        for (_, ban) in &self.bans
        {
            if ban.is_match(&ip)
            {
                return Some("You are banned.".to_string());
            }
        }
        let mut title = arg_title.clone();
        if !isadmin
        {
            title = "".to_string();
        }
        let newid = 
        if let Some(board) = self.boards.get(boardurl)
        {
            for (_, ban) in &board.bans
            {
                if ban.is_match(&ip)
                {
                    return Some("You are banned.".to_string());
                }
            }
            board.highest_post_id+1
        }
        else
        {
            return Some(format!("no such board \"{}\"", boardurl));
        };
        self.insert_post(boardurl, newid, name, text, &ip.to_string(), nonce, &title, isadmin && show_isadmin, ismod && show_isadmin)
    }
    fn insert_post(&mut self, boardurl : &String, id : u64, arg_name : &String, arg_text : &String, ip : &String, nonce : &String, title : &String, show_isadmin : bool, mut show_ismod : bool) -> Option<String> // Some() if error, None if success
    {
        if show_isadmin { show_ismod = false; }
        
        let mut name = arg_name.clone();
        let mut text = arg_text.clone();
        name = name.trim().to_string();
        if name == ""
        {
            name = "Anonymous".to_string();
        }
        text = text.trim().to_string();
        if text != ""
        {
            if let Some(board) = self.boards.get_mut(boardurl)
            {
                // TODO: dynamic time limit based on post length, bottoming out at 1 second for a one character post, maxing out at 30 seconds for a couple short paragraphs
                if let Some(time) = board.latest_time_per_ip.get(ip)
                {
                    let difference = get_unix_ms() - time;
                    if difference < 5*1000 // 5 seconds
                    {
                        return Some(format!("post is too soon. try again in {} seconds", ((5*1000 - difference) as f64/1000.0).ceil() as u64));
                    }
                }
                if board.seen_post_nonces.contains(nonce)
                {
                    return Some(format!("attempted to submit the same post twice"))
                }
                if !board.posts.contains_key(&id)
                {
                    if id <= board.highest_post_id
                    {
                        Some(format!("attempted to non-chronologically insert post id {} (into board {}) which is not larger than the latest ever post {}", id, boardurl, board.highest_post_id))
                    }
                    else 
                    {
                        // if there's a title it means this post is the OP of a new thread
                        if title != ""
                        {
                            board.current_thread += 1;
                            board.threads.insert(board.current_thread, (title.clone(), HashSet::<u64>::new()));
                        }
                        if let Some((_, posts)) = board.threads.get_mut(&board.current_thread)
                        {
                            board.latest_time_per_ip.insert(ip.clone(), get_unix_ms());
                            
                            posts.insert(id);
                            board.posts.insert(id, PostData{id, thread : board.current_thread, name, text, ip : ip.clone(), unix_ms : get_unix_ms(), edited_unix_mx : 0, show_isadmin, show_ismod});
                            board.highest_post_id = id;
                            board.seen_post_nonces.insert(nonce.clone());
                            None
                        }
                        else
                        {
                            Some(format!("failed to find current thread"))
                        }
                    }
                }
                else
                {
                    Some(format!("post with id {} already exists", id))
                }
            }
            else
            {
                Some(format!("no such board \"{}\"", boardurl))
            }
        }
        else
        {
            Some("message must not be blank".to_string())
        }
    }
    fn default_post_form(&self, boardurl : &String, isadmin : bool, ismod : bool) -> String
    {
        self.prefill_post_form(boardurl, &"".to_string(), &"".to_string(), &"".to_string(), isadmin, ismod)
    }
    fn prefill_post_form(&self, boardurl : &String, name_prefill : &String, content_prefill : &String, title_prefill : &String, isadmin : bool, ismod : bool) -> String
    {
        // TODO: migrate to template
        let title_box =
        if isadmin | ismod
        {
            format!("<input type=\"checkbox\" name=\"show_isadmin\">Post as {}<br><input type=\"text\" name=\"title\" placeholder=\"Title (make new thread)\" {}>", &if isadmin { "admin" } else { "moderator" }, &entity_escape(title_prefill))
        }
        else
        {
            "<input type=\"hidden\" name=\"title\" value=\"\"><!-- used for admins to make new threads - won't do anything even if you edit it in with a value because you don't have an admin session --><input type=\"hidden\" name=\"show_isadmin\" value=\"\"><!-- used for admins to post as an admin - again, won't do anything for you even if you edit it in -->".to_string()
        };
        
        let double_post_prevention_nonce = random_base_62(16);
        format!(
"<form action=\"/{0}/submit\" method=\"POST\" enctype=\"multipart/form-data\">
    {4}
    <input type=\"hidden\" name=\"double_post_prevention\" value=\"{1}\">
    <input {2} placeholder=\"Anonymous\" type=\"text\" name=\"username\"> <button>Post</button><br>
    <textarea name=\"content\" maxlength=\"5000\" style=\"width:500px; height:200px\">{3}</textarea>
</form>", url_escape(boardurl), &double_post_prevention_nonce, & if name_prefill == "" { "".to_string() } else { format!("value=\"{}\"", &entity_escape(name_prefill)) }, &entity_escape(content_prefill), &title_box )
    }
    
    fn new_admin(&mut self, name : &String) -> Result<String, String>
    {
        let defaultpassword = random_base_62(32);
        let passhash = self.hash_password(&defaultpassword).unwrap();
        
        if !self.admins.contains_key(name)
        {
            self.admins.insert(name.clone(), AdminData{name : name.clone(), passhash});
        
            Ok(defaultpassword)
        }
        else
        {
            Err(format!("Admin \"{}\" already exists", name))
        }
    }
    
    fn new_board_admin(&mut self, boardurl : &String, name : &String) -> Result<String, String>
    {
        if !self.boards.contains_key(boardurl)
        {
            return Err(format!("No such board \"{}\"", boardurl));
        }
        
        let defaultpassword = random_base_62(32);
        let passhash = self.hash_password(&defaultpassword).unwrap();
        
        let board = self.boards.get_mut(boardurl).unwrap();
        
        if !board.admins.contains_key(name)
        {
            board.admins.insert(name.clone(), AdminData{name : name.clone(), passhash});
        
            Ok(defaultpassword)
        }
        else
        {
            Err(format!("Admin \"{}\" already exists", name))
        }
    }
}

fn load_to_string(fname : &str) -> std::io::Result<String>
{
    let mut file = File::open(fname)?;
    let mut string = String::new();
    file.read_to_string(&mut string)?;
    return Ok(string);
}
fn init() -> std::io::Result<ServerData>
{
    let template = load_to_string("template.html")?;
    
    let mut server = ServerData { template, boards : HashMap::new(), hasher_config : ScryptParams::new(15, 8, 1).unwrap(), admins : HashMap::new(), admin_sessions : HashMap::new(), admin_login_attempt_log : Vec::new(), name_bbcode : "".to_string(), announcement_bbcode : "".to_string(), bans : HashMap::new(), highest_ban_id: 0, admin_action_log: Vec::new() };
    server.make_new_board(&"meta".to_string(), &"Meta".to_string());
    server.insert_post(&"meta".to_string(), 1, &"System".to_string(), &"This is the default post posted automatically for testing purposes. <test punctuation>".to_string(), &"0.0.0.0".to_string(), &"".to_string(), &"Test Thread".to_string(), true, false);
    
    let defaultname = "admin";
    let password = server.new_admin(&defaultname.to_string()).unwrap();
    println!("default admin login is:\n{}\n{}", defaultname, password);
    
    let defaultname = "moderator";
    let password = server.new_board_admin(&"meta".to_string(), &defaultname.to_string()).unwrap();
    println!("default board admin login for board #meta is:\n{}\n{}", defaultname, password);
    
    // TODO: make a bbcode-like formatting system
    server.name_bbcode = "[r=かたばみやど]片喰宿[/r]へようこそ".to_string();
    server.announcement_bbcode = "※このサイトは工事中。今しばらく完成までお待ちください。ソフトを更新・再起動したら全てが消える。".to_string();
    
    // this was for testing bans
    /*
    if let Some(banrange) = string_to_banrange(&"127.0.0.1/32".to_string())
    {
        server.bans.push(banrange);
    }
    */
    
    Ok(server)
}

fn get_unix_ms() -> u64
{
    let result = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
    if let Ok(duration) = result
    {
        duration.as_secs()*1000 + duration.subsec_millis() as u64
    }
    else
    {
        0 // shouldn't be accessible unless the system clock is extremely broken or you're running this software in the year 1960
    }
}

fn parse_big(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    let re = Regex::new(&r#"(.*?)\[big\](.*?)\[/big\](.*)"#).unwrap();
    
    if let Some(caps) = re.captures(bbcode)
    {
        let location = caps.get(1).unwrap().end();
        let start_html = bbcode_to_html(&caps.get(1).unwrap().as_str().to_string(), isadmin);
        let inner_html = bbcode_to_html(&caps.get(2).unwrap().as_str().to_string(), isadmin);
        let   end_html = bbcode_to_html(&caps.get(3).unwrap().as_str().to_string(), isadmin);
        
        Some((location, format!("{0}<span class=\"bbcodebig\">{1}</span>{2}", &start_html, &inner_html, &end_html)))
    }
    else
    {
        None
    }
}

fn parse_simple(bbcode : &String, isadmin : bool, tag : &'static str) -> Option<(usize, String)>
{
    let re = Regex::new(&format!(r#"(.*?)\[{0}\](.*?)\[/{0}\](.*)"#, tag)).unwrap();
    
    if let Some(caps) = re.captures(bbcode)
    {
        let location = caps.get(1).unwrap().end();
        let start_html = bbcode_to_html(&caps.get(1).unwrap().as_str().to_string(), isadmin);
        let inner_html = bbcode_to_html(&caps.get(2).unwrap().as_str().to_string(), isadmin);
        let   end_html = bbcode_to_html(&caps.get(3).unwrap().as_str().to_string(), isadmin);
        
        Some((location, format!("{1}<{0}>{2}</{0}>{3}", tag, &start_html, &inner_html, &end_html)))
    }
    else
    {
        None
    }
}

fn parse_b(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    parse_simple(bbcode, isadmin, "b")
}

fn parse_i(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    parse_simple(bbcode, isadmin, "i")
}

fn parse_u(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    parse_simple(bbcode, isadmin, "u")
}

fn parse_br(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    let re = Regex::new(r#"(?s)(.*?)\[br\](.*)"#).unwrap();
    
    if let Some(caps) = re.captures(bbcode)
    {
        let location = caps.get(1).unwrap().end();
        let start_html = bbcode_to_html(&caps.get(1).unwrap().as_str().to_string(), isadmin);
        let end_html = bbcode_to_html(&caps.get(2).unwrap().as_str().to_string(), isadmin);
        
        Some((location, format!("{0}<br>{1}", &start_html, &end_html)))
    }
    else
    {
        None
    }
}

fn parse_simple_url(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    let re = Regex::new(r#"(?s)(.*?)\[url\](.*?)\[/url\](.*)"#).unwrap();
    
    if let Some(caps) = re.captures(bbcode)
    {
        let location = caps.get(1).unwrap().end();
        let start_html = bbcode_to_html(&caps.get(1).unwrap().as_str().to_string(), isadmin);
        let mut inner = caps.get(2).unwrap().as_str().trim().to_string();
        if !inner.starts_with("https://") && !inner.starts_with("http://") && !inner.starts_with("ftp://") && !inner.starts_with("//")
        {
            inner = "https://".to_string() + &inner;
        }
        let inner_escaped = entity_escape(&inner);
        let end_html = bbcode_to_html(&caps.get(3).unwrap().as_str().to_string(), isadmin);
        
        Some((location, format!("{0}<a href=\"{1}\" target=\"_blank\" rel=\"noopener noreferrer\" referrerpolicy=\"no-referrer\">{1}</a>{2}", &start_html, &inner_escaped, &end_html)))
    }
    else
    {
        None
    }
}
fn parse_admin_url(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    let re = Regex::new(r#"(?s)(.*?)\[url="([^"]*)"\](.*?)\[/url\](.*)"#).unwrap();
    
    if let Some(caps) = re.captures(bbcode)
    {
        let location = caps.get(1).unwrap().end();
        let start_html = bbcode_to_html(&caps.get(1).unwrap().as_str().to_string(), isadmin);
        let mut argument = caps.get(2).unwrap().as_str().to_string();
        if !argument.starts_with("https://") && !argument.starts_with("http://") && !argument.starts_with("ftp://") && !argument.starts_with("//") && !argument.starts_with("/")
        {
            argument = "https://".to_string() + &argument;
        }
        let argument_escaped = entity_escape(&argument);
        let inner = bbcode_to_html(&caps.get(3).unwrap().as_str().to_string(), isadmin);
        let end_html = bbcode_to_html(&caps.get(4).unwrap().as_str().to_string(), isadmin);
        
        Some((location, format!("{0}<a href=\"{1}\" target=\"_blank\" rel=\"noopener noreferrer\" referrerpolicy=\"no-referrer\">{2}</a>{3}", &start_html, &argument_escaped, &inner, &end_html)))
    }
    else
    {
        None
    }
}
fn parse_admin_badurl(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    let re = Regex::new(r#"(?s)(.*?)\[badurl="([^"]*)"\](.*?)\[/badurl\](.*)"#).unwrap();
    
    if let Some(caps) = re.captures(bbcode)
    {
        let location = caps.get(1).unwrap().end();
        let start_html = bbcode_to_html(&caps.get(1).unwrap().as_str().to_string(), isadmin);
        let mut argument = caps.get(2).unwrap().as_str().to_string();
        let argument_escaped = "/".to_string() + &entity_escape(&argument);
        let inner = bbcode_to_html(&caps.get(3).unwrap().as_str().to_string(), isadmin);
        let end_html = bbcode_to_html(&caps.get(4).unwrap().as_str().to_string(), isadmin);
        
        Some((location, format!("{0}<a href=\"{1}\">{2}</a>{3}", &start_html, &argument_escaped, &inner, &end_html)))
    }
    else
    {
        None
    }
}

fn parse_ruby(bbcode : &String, isadmin : bool) -> Option<(usize, String)>
{
    let re = Regex::new(r#"(?s)(.*?)\[r=([^\]]*)\](.*?)\[/r\](.*)"#).unwrap();
    
    if let Some(caps) = re.captures(bbcode)
    {
        let location = caps.get(1).unwrap().end();
        let start_html    = bbcode_to_html(&caps.get(1).unwrap().as_str().to_string(), isadmin);
        let argument_html = bbcode_to_html(&caps.get(2).unwrap().as_str().to_string(), isadmin);
        let inner_html    = bbcode_to_html(&caps.get(3).unwrap().as_str().to_string(), isadmin);
        let   end_html    = bbcode_to_html(&caps.get(4).unwrap().as_str().to_string(), isadmin);
        
        Some((location, format!("{0}<ruby>{2}<rp>(</rp><rt>{1}</rt><rp>)</rp></ruby>{3}", &start_html, &argument_html, &inner_html, &end_html)))
    }
    else
    {
        None
    }
}

fn bbcode_to_html(bbcode : &String, isadmin : bool) -> String
{
    let parsers : Vec<fn(&String, bool)->Option<(usize, String)>> =
    if isadmin { vec!(parse_b, parse_i, parse_u, parse_br, parse_big, parse_ruby, parse_simple_url, parse_admin_url, parse_admin_badurl) }
    else       { vec!(parse_b, parse_i, parse_u, parse_br, parse_big, parse_ruby, parse_simple_url) };
    
    let mut lowest = std::usize::MAX;
    let mut lowest_text = entity_escape(bbcode);
    for parser in parsers
    {
        if let Some((start, text)) = parser(bbcode, isadmin)
        {
            if start < lowest
            {
                lowest = start;
                lowest_text = text;
            }
        }
    }
    
    return lowest_text;
}

fn main() -> Result<(), std::io::Error>
{
    //println!("bbcode to html:\n{}", &bbcode_to_html(&"[r=test]テスト[/r][i][b]>test<[b][i]test2[/b][/i][b]asdf[/b]a[url=\"google.com/\"]test link[/url]".to_string(), true));
    //return Ok(());
    
    let server = Mutex::new(init()?);
    
    println!("finished loading");
    
    let re = Regex::new(r"([?&;])([^=&;#]+)(=([^&;#]+))?").unwrap();
    
    let args = std::env::args().collect::<Vec<String>>();
    let address =
    if args.len() <= 1
    {
        "localhost:8080"
    }
    else
    {
        args.get(1).unwrap()
    };
    
    rouille::start_server(address, move |request|
    {
        if let Ok(mut server) = server.lock()
        {
            let remote_ip = request.remote_addr().ip();
            
            let mystr = "&".to_string()+&percent_encoding::percent_decode(request.raw_query_string().as_bytes()).decode_utf8_lossy().into_owned();
            let matches = re.find_iter(mystr.as_str());
            let cookies_list = rouille::input::cookies(request).map(|x| (x.0.to_string(), x.1.to_string())).collect::<Vec<(String, String)>>();
            
            let mut cookies = HashMap::<String, String>::new();
            for pair in cookies_list
            {
                cookies.insert(pair.0, pair.1);
            }
            
            let mut args = HashMap::<&str, &str>::new();
            for mymatch in matches
            {
                let split = mymatch.as_str().splitn(2, "=").collect::<Vec<_>>();
                if split.len() == 1
                {
                    args.insert(&split[0][1..], "");
                }
                else
                {
                    args.insert(&split[0][1..], split[1]);
                }
            }
            
            let global_session_id = cookies.get("adminsession").cloned().unwrap_or("".to_string());
            
            let global_admin_session = 
            if let Some(session_id) = cookies.get("adminsession")
            {
                server.get_admin_session_from_string(&remote_ip, &session_id)
            }
            else
            {
                None
            };
            
            let mut isadmin =
            if let Some(ref _unused) = global_admin_session
            {
                true
            }
            else
            {
                false
            };
            
            let board_admin_session = 
            if let Some(session_cookie) = cookies.get("boardadminsession")
            {
                let fields = session_cookie.rsplitn(2, ":").collect::<Vec<&str>>();
                if fields.len() >= 2
                { server.get_board_admin_session_from_string(&fields[1].to_string(), &remote_ip, &fields[0].to_string()) }
                else
                { None }
            }
            else
            {
                None
            };
            
            let mut response = router!(request,
                (GET) (/) =>
                {
                    server.directory_default()
                },
                (GET) (/admin) =>
                {
                    if let Some(ref sessdata) = global_admin_session
                    { server.generate_admin_page_for_session(sessdata.clone()) }
                    else
                    { server.generate_admin_login_page() }
                },
                (GET) (/admin/) =>
                {
                    if let Some(ref sessdata) = global_admin_session
                    { server.generate_admin_page_for_session(sessdata.clone()) }
                    else
                    { server.generate_admin_login_page() }
                },
                (POST) (/admin/action/{action : String}) =>
                {
                    server.attempt_admin_action(&global_admin_session, &action, &remote_ip, request)
                },
                (GET) (/{boardurl : String}/admin) =>
                {
                    let isboardadmin = board_admin_session.is_some() && board_admin_session.as_ref().unwrap().boardurl == boardurl;
                    
                    if let Some(ref sessdata) = global_admin_session
                    { server.generate_board_admin_page_for_session(&boardurl, sessdata.clone()) }
                    else if isboardadmin
                    {
                        let sessdata = board_admin_session.clone().unwrap();
                        server.generate_board_admin_page_for_session(&boardurl, sessdata.clone())
                    }
                    else
                    { server.generate_board_admin_login_page(&boardurl) }
                },
                (GET) (/{boardurl : String}/admin/) =>
                {
                    let isboardadmin = board_admin_session.is_some() && board_admin_session.as_ref().unwrap().boardurl == boardurl;
                    
                    if let Some(ref sessdata) = global_admin_session
                    { server.generate_board_admin_page_for_session(&boardurl, sessdata.clone()) }
                    else if isboardadmin
                    {
                        let sessdata = board_admin_session.clone().unwrap();
                        server.generate_board_admin_page_for_session(&boardurl, sessdata.clone())
                    }
                    else
                    { server.generate_board_admin_login_page(&boardurl) }
                },
                (POST) (/{boardurl : String}/admin/action/{action : String}) =>
                {
                    let isboardadmin = board_admin_session.is_some() && board_admin_session.as_ref().unwrap().boardurl == boardurl;
                    
                    if isadmin || action == "login"
                    { server.attempt_board_admin_action(&global_admin_session, &boardurl, &action, &remote_ip, request) }
                    else if isboardadmin
                    { server.attempt_board_admin_action(&board_admin_session, &boardurl, &action, &remote_ip, request) }
                    else
                    { rouille::Response::empty_404() }
                },
                (GET) (/{boardurl : String}) =>
                {
                    let isboardadmin = board_admin_session.is_some() && board_admin_session.as_ref().unwrap().boardurl == boardurl;
                    
                    server.board_frontpage(&boardurl, isadmin, isboardadmin)
                },
                (GET) (/{boardurl : String}/) =>
                {
                    let isboardadmin = board_admin_session.is_some() && board_admin_session.as_ref().unwrap().boardurl == boardurl;
                    
                    server.board_frontpage(&boardurl, isadmin, isboardadmin)
                },
                (GET) (/{boardurl : String}/{thread_id : u64}) =>
                {
                    let isboardadmin = board_admin_session.is_some() && board_admin_session.as_ref().unwrap().boardurl == boardurl;
                    
                    server.search(&boardurl, thread_id, isadmin, isboardadmin)
                },
                (GET) (/{boardurl : String}/archive) =>
                {
                    server.board_archive(&boardurl)
                },
                (POST) (/{boardurl : String}/submit) =>
                {
                    let isboardadmin = board_admin_session.is_some() && board_admin_session.as_ref().unwrap().boardurl == boardurl;
                    
                    let mut data = try_or_400!(post_input!(request, {
                        title: String,
                        username: String,
                        content: String,
                        double_post_prevention: String,
                        show_isadmin: bool,
                    }));
                    
                    if data.username.chars().count() > 100
                    {
                        server.board_with_error_and_prefill(&boardurl, &"username too long (100 char max)".to_string(), &data.username, &data.content, &data.title, isadmin, isboardadmin)
                    }
                    else if data.content.chars().count() > 6000
                    {
                        server.board_with_error_and_prefill(&boardurl, &"message too long (6000 char max)".to_string(), &data.username, &data.content, &data.title, isadmin, isboardadmin)
                    }
                    else if data.double_post_prevention.chars().count() > 32
                    {
                        server.board_with_error_and_prefill(&boardurl, &"double post prevention nonce too long (32 char max)".to_string(), &data.username, &data.content, &data.title, isadmin, isboardadmin)
                    }
                    else if let Some(errormessage) = server.insert_new_post(&boardurl, &data.username, &data.content, &remote_ip, &data.double_post_prevention, &data.title, isadmin, isboardadmin, data.show_isadmin)
                    {
                        server.board_with_error_and_prefill(&boardurl, &errormessage, &data.username, &data.content, &data.title, isadmin, isboardadmin)
                    }
                    else
                    {
                        rouille::Response::redirect_302(format!("/{}", url_escape(&boardurl)))
                    }
                },
                _ => rouille::Response::empty_404()
            );
            if isadmin
            {
                if let Some(ref sessdata) = global_admin_session
                {
                    server.refresh_admin_session(sessdata.clone(), &mut response, &global_session_id);
                }
            }
            response
        }
        else
        {
            println!("Error: failed to lock server mutex");
            rouille::Response {
                status_code: 503,
                headers: vec![],
                data: rouille::ResponseBody::empty(),
                upgrade: None,
            }
        }
    });
}