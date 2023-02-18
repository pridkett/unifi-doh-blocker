unifi-doh-blocker
=================

Patrick Wagstrom &lt;160672+pridkett@users.noreply.github.com&gt;

February 2023

Overview
--------

This is part of my continuing process of ensuring that systems can't reach out and get hostnames unless I expressly permit them to do that. Basically, it really clamps down on devices relaying information back to their mothership or being able to serve ads. It's become particularly nasty now that some devices have hardcoded `8.8.8.8`/`dns.google` as DNS-over-HTTPS servers - renderign my blocks on port 53/853 useless.

The only way that I've found I can easily do this is to create a group within my Unifi controller, and then block all DNS-over-HTTPS traffic every DNS-over-HTTPS servers that you want to block. This program does that for me.

It is almost certainly overkill.

Installation
------------

```bash
go build
```

Usage
-----

```bash
./unifi-doh-blocker -h
Usage of ./unifi-doh-blocker:
  -controller string
        The URL of the Unifi controller (default "https://unifi.example.com:8443")
  -password string
        The password for the Unifi controller
  -site string
        The site to use (default "default")
  -username string
        The username for the Unifi controller
```

License
-------

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

Acknowledgments
---------------

* [Unifi API](https://ubntwiki.com/products/software/unifi-controller/api): This provided the start for being able reverse engineer the REST interface required for the project.ß

