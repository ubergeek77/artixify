# artixify

A hilariously overengineered "frontend" for [takeover.sh](https://github.com/marcan/takeover.sh).

*Instantly improve your Linux server!*

These scripts will nuke the server they're run on and install a customizable and slightly opinionated Artix-runit server, without needing to use an install .iso or recovery environment.

It provisions a small Alpine Linux tmpfs, uses [takeover.sh](https://github.com/marcan/takeover.sh) to make that the new root, then runs [artix-bootstrap](https://gitea.artixlinux.org/artix/artix-bootstrap) to perform the install.

How to use
- Download the scripts
- Uncomment/edit `artixify.env` with your desired settings
- Run `artixify-stage1.sh`, and be prepared to reinstall your server manually if something breaks
- The server will reboot itself, and upon successful login, you'll find the install log at `/var/log/artixify.log` on the new system

Things to keep in mind:
- You will need an SSH public key for which you have the private key. This is how you will SSH to your new system. Password logins are lame.
- `root` is intentionally missing a password. The goal is to have you set one yourself with `sudo`
- If you don't override `NEW_PASS`, then your new account password will be `artix`
- `ufw` is installed by default but is not enabled by default. Don't forget to enable it!
- I customize `neofetch` with some settings I think are nice, and have it run on login. Feel free to modify the configs if you don't like that, or simply remove `neofetch` from the `EXTRA_PKGS` install variable.
- Take a look at `artixify-stage1.sh` to see which packages/PKGBUILD packages I include by default. Feel free to delete those lines or add your own.
  - Since I made this script for myself, I include my own forked versions of some packages I like to use:
  - [svlogger](https://github.com/ubergeek77/svlogger) - auto-enable logging for runit services, written by bahamas10 and made into PKGBUILD by me.
  - [vsv](https://github.com/ubergeek77/vsv) - better frontend for `sv`, written by bahamas10 and made into PKGBUILD by me.