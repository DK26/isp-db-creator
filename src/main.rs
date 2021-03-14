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

struct Entry<'a> {
    // Unique Fields: 22:{'country', 'descr', 'remarks', 'admin-c', 'org', 'netname', 'inetnum', 'abuse-c', 'status',
    // 'created', 'geoloc', 'language', 'last-modified', 
    //'source', 'mnt-by', 'mnt-irt', 'mnt-domains', 'mnt-lower', 'mnt-routes', 'tech-c', 'notify', 'sponsoring-org'}
    from_inetnum: u32,
    to_inteum: u32,
    country: &'a str,
    language: &'a str,
    descr: &'a str
}

fn main() {

    // Download RIPE: https://ftp.ripe.net/ripe/dbase/ripe.db.gz
    //  - Extract

    // Threads
    // =======
    // 1. `ripe.db` entry scanner job - Detects entry lines and duplicates them into the raw entries channel.
    // 3. SQLite job - Listening on parsed entries channel. Terminates with the channel.
    // 2. `ripe.db` entry parser job - Receives entries from raw entries channel, parsing into parsed entities.

    
}