// MIT License

// Copyright (c) 2021 David Krasnitsky

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::{
    env, 
    error::Error, 
    fs::{
         File, 
         OpenOptions, 
         read_to_string
    }, 
    io::{
        self,
        BufReader, 
        Lines, 
        prelude::*
    }, 
    net::{
        IpAddr, 
        Ipv4Addr, 
        Ipv6Addr
    }, 
    path::Path, 
    time::Instant
};
use lazy_static::lazy_static;
use regex::Regex;

// enum Country {
//     Unknown(""),
//     Israel("il"),
//     USA,
//     Lithuania
// }

struct inetnum(u32, u32);
struct inet6num(u128, u128);
struct mntner;
struct role;
struct person;
struct route;


struct Entry<'a> {
    // Unique Fields: 22:{'country', 'descr', 'remarks', 'admin-c', 'org', 'netname', 'inetnum', 'abuse-c', 'status',
    // 'created', 'geoloc', 'language', 'last-modified', 
    //'source', 'mnt-by', 'mnt-irt', 'mnt-domains', 'mnt-lower', 'mnt-routes', 'tech-c', 'notify', 'sponsoring-org'}
    inetnum_from: u32,
    inteum_to: u32,
    netname: &'a str,
    descr: &'a str,
    country: &'a str,
    language: &'a str,
    org: &'a str,
    admin_c: &'a str,
    tech_c: &'a str,
    status: &'a str,
    mnt_by: &'a str,
    created: u32,
    last_modified: u32,
    source: &'a str,
    remarks: &'a str,
}

// impl<'a> Default for Entry<'a> {

//     fn default() -> Self {
//         Self {
//             inetnum_from: 0,
//             inteum_to: 0,
//             country: "",
//             language: "",
//             descr: ""
//         }
//     }

// }

/*  
    Options
    =======
    1. Extract `ripe.db.gz` / `ripe.db`
    2. Download: 
         - https://ftp.ripe.net/ripe/dbase/ripe.db.gz
         - https://ftp.afrinic.net/pub/dbase/afrinic.db.gz
         - https://ftp.apnic.net/pub/apnic/whois/apnic.db.inetnum.gz
         - https://ftp.apnic.net/pub/apnic/whois/apnic.db.inet6num.gz
         - ftp://ftp.arin.net/pub/rr/arin.db.gz
         - ftp://ftp.arin.net/pub/rr/arin-nonauth.db.gz
         - ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest
         - https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz
         - https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz

    3. Download & Extract
    
    Extract Options
    ===============
    1. `SQLite` + Compress (Bonus: Compose in-RAM, serialize a backup when done.)
    2. `.csv` + Compress 
    3. `.xlsx` + Compress 
    4. `PostgreSQL`
    5. others

    Threads
    =======
    1. `ripe.db` entry scanner job - Detects entry lines and duplicates them into the raw entries channel.
    2. `ripe.db` entry parser job - Receives entries from raw entries channel, parsing into parsed entities with work-stealing.
    3. SQLite job - Listening on parsed entries channel. Terminates with the channel.

    Parsing Formats
    ===============
    1. RPSL (https://en.wikipedia.org/wiki/Routing_Policy_Specification_Language)

        https://tools.ietf.org/html/rfc2622
        https://tools.ietf.org/html/rfc2650

        - mntner Class
        Attribute  Value                   Type
        mntner     <object-name>           mandatory, single-valued, class key
        descr      <free-form>             mandatory, single-valued
        auth       see description in text mandatory, multi-valued
        upd-to     <email-address>         mandatory, multi-valued
        mnt-nfy    <email-address>         optional, multi-valued
        tech-c     <nic-handle>            mandatory, multi-valued
        admin-c    <nic-handle>            optional, multi-valued
        remarks    <free-form>             optional, multi-valued
        notify     <email-address>         optional, multi-valued
        mnt-by     list of <mntner-name>   mandatory, multi-valued
        changed    <email-address> <date>  mandatory, multi-valued
        source     <registry-name>         mandatory, single-valued

        - Person Class
        Attribute  Value                   Type
        person     <free-form>             mandatory, single-valued
        nic-hdl    <nic-handle>            mandatory, single-valued, class key
        address    <free-form>             mandatory, multi-valued
        phone      see description in text mandatory, multi-valued
        fax-no     same as phone           optional, multi-valued
        e-mail     <email-address>         mandatory, multi-valued

        - Role Class
        Attribute  Value                    Type
        role       <free-form>              mandatory, single-valued
        nic-hdl    <nic-handle>             mandatory, single-valued,
                                            class key
        trouble    <free-form>              optional, multi-valued
        address    <free-form>              mandatory, multi-valued
        phone      see description in text  mandatory, multi-valued
        fax-no     same as phone            optional, multi-valued
        e-mail     <email-address>          mandatory, multi-valued

        - Route Class
        Attribute     Value                      Type
        route         <address-prefix>           mandatory, single-valued,
                                                    class key
        origin        <as-number>                mandatory, single-valued,
                                                    class key
        member-of     list of <route-set-names>  optional, multi-valued
                        see Section 5
        inject        see Section 8              optional, multi-valued
        components    see Section 8              optional, single-valued
        aggr-bndry    see Section 8              optional, single-valued
        aggr-mtd      see Section 8              optional, single-valued
        export-comps  see Section 8              optional, single-valued
        holes         see Section 8              optional, multi-valued


    Maintainer (ISP) - mntner
    - mnt-by: <ownership by a `mntner` value>

    Role - role
    Person - person
    Route (AS) - route

*/

type BufferedLinesResult = io::Result<Lines<BufReader<File>>>;

fn read_buffered_lines<P: AsRef<Path>>(filepath: P) -> BufferedLinesResult {
    let file = File::open(filepath)?;
    Ok(BufReader::new(file).lines())
}

fn main() -> Result<(), Box<dyn Error>> {

    let database_file = env::args().nth(1).expect("Missing data base file");

    let database_file = Path::new(&database_file);

    let start = Instant::now();

    if let Ok(lines) = read_buffered_lines(database_file) {

        for line in lines {

            // TODO: Scan database file(s). 
            // TODO: Detect entries
            // TODO: Send raw entries to parsing channel

        }

    }
    
    Ok(())

} // main()
