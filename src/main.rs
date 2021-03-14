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

// enum Country {
//     Unknown(""),
//     Israel("il"),
//     USA,
//     Lithuania
// }

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

fn main() {

    // Options
    // =======
    // 1. Extract `ripe.db.gz` / `ripe.db`
    // 2. Download: 
    //      - https://ftp.ripe.net/ripe/dbase/ripe.db.gz
    //      - https://ftp.afrinic.net/pub/dbase/afrinic.db.gz
    //      - https://ftp.apnic.net/pub/apnic/whois/apnic.db.inetnum.gz
    //      - https://ftp.apnic.net/pub/apnic/whois/apnic.db.inet6num.gz
    //      - ftp://ftp.arin.net/pub/rr/arin.db.gz
    //      - ftp://ftp.arin.net/pub/rr/arin-nonauth.db.gz
    //      - ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest
    //      - https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz
    //      - https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz

    // 3. Download & Extract
    
    // Extract Options
    // ===============
    // 1. `SQLite` + Compress 
    // 2. `.csv` + Compress 
    // 3. `.xlsx` + Compress 
    // 4. `PostgreSQL`
    // 5. others

    // Threads
    // =======
    // 1. `ripe.db` entry scanner job - Detects entry lines and duplicates them into the raw entries channel.
    // 2. `ripe.db` entry parser job - Receives entries from raw entries channel, parsing into parsed entities with work-stealing.
    // 3. SQLite job - Listening on parsed entries channel. Terminates with the channel.

}
