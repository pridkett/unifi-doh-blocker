unifi-doh-blocker
=================

Patrick Wagstrom &lt;160672+pridkett@users.noreply.github.com&gt;

February 2023

Overview
--------

This is part of my continuing process of ensuring that systems can't reach out and get hostnames unless I expressly permit them to do that. Basically, it really clamps down on devices relaying information back to their mothership or being able to serve ads. It's become particularly nasty now that some devices have hardcoded `8.8.8.8`/`dns.google` as DNS-over-HTTPS servers - renderign my blocks on port 53/853 useless.

The only way that I've found I can easily do this is to create a group within my Unifi controller, and then block all DNS-over-HTTPS traffic every DNS-over-HTTPS servers that you want to block. This program does that for me.

