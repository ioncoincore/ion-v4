# Sample init scripts and service configuration for iond

Sample scripts and configuration files for systemd, Upstart and OpenRC
can be found in the contrib/init folder.

- [contrib/init/iond.service](contrib/init/iond.service):    systemd service unit configuration
- [contrib/init/iond.openrc](contrib/init/iond.openrc):     OpenRC compatible SysV style init script
- [contrib/init/iond.openrcconf](contrib/init/iond.openrcconf): OpenRC conf.d file
- [contrib/init/iond.conf](contrib/init/iond.conf):       Upstart service configuration file
- [contrib/init/iond.init](contrib/init/iond.init):       CentOS compatible SysV style init script

Table of Contents
-----------------
- [Sample init scripts and service configuration for iond](#Sample-init-scripts-and-service-configuration-for-iond)
  - [Table of Contents](#Table-of-Contents)
  - [1. Service User](#1-Service-User)
  - [2. Configuration](#2-Configuration)
  - [3. Paths](#3-Paths)
    - [Linux](#Linux)
    - [macOS](#macOS)
  - [4. Installing Service Configuration](#4-Installing-Service-Configuration)
    - [systemd](#systemd)
    - [OpenRC](#OpenRC)
    - [Upstart (for Debian/Ubuntu based distributions)](#Upstart-for-DebianUbuntu-based-distributions)
    - [CentOS](#CentOS)
    - [macOS](#macOS-1)
  - [5. Auto-respawn](#5-Auto-respawn)


## 1. Service User

All three Linux startup configurations assume the existence of a "ion" user
and group.  They must be created before attempting to use these scripts.
The macOS configuration assumes iond will be set up for the current user.

## 2. Configuration

At a bare minimum, iond requires that the rpcpassword setting be set
when running as a daemon.  If the configuration file does not exist or this
setting is not set, iond will shutdown promptly after startup.

This password does not have to be remembered or typed as it is mostly used
as a fixed token that iond and client programs read from the configuration
file, however it is recommended that a strong and secure password be used
as this password is security critical to securing the wallet should the
wallet be enabled.

If iond is run with the "-server" flag (set by default), and no rpcpassword is set,
it will use a special cookie file for authentication. The cookie is generated with random
content when the daemon starts, and deleted when it exits. Read access to this file
controls who can access it through RPC.

By default the cookie is stored in the data directory, but it's location can be overridden
with the option '-rpccookiefile'.

This allows for running iond without having to do any manual configuration.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

For an example configuration file that describes the configuration settings,
see contrib/debian/examples/ioncoin.conf.

## 3. Paths

### Linux

All three configurations assume several paths that might need to be adjusted.

Binary:              /usr/bin/iond
Configuration file:  /etc/ion/ioncoin.conf
Data directory:      /var/lib/iond
PID file:            `/var/run/iond/iond.pid` (OpenRC and Upstart) or `/run/iond/iond.pid` (systemd)
Lock file:           `/var/lock/subsys/iond` (CentOS)

The configuration file, PID directory (if applicable) and data directory
should all be owned by the ion user and group.  It is advised for security
reasons to make the configuration file and data directory only readable by the
ion user and group.  Access to ion-cli and other iond rpc clients
can then be controlled by group membership.

NOTE: When using the systemd .service file, the creation of the aforementioned
directories and the setting of their permissions is automatically handled by
systemd. Directories are given a permission of 710, giving the ion group
access to files under it _if_ the files themselves give permission to the
ion group to do so (e.g. when `-sysperms` is specified). This does not allow
for the listing of files under the directory.

NOTE: It is not currently possible to override `datadir` in
`/etc/ion/ioncoin.conf` with the current systemd, OpenRC, and Upstart init
files out-of-the-box. This is because the command line options specified in the
init files take precedence over the configurations in
`/etc/ion/ioncoin.conf`. However, some init systems have their own
configuration mechanisms that would allow for overriding the command line
options specified in the init files (e.g. setting `BITCOIND_DATADIR` for
OpenRC).

### macOS

Binary:              `/usr/local/bin/iond`
Configuration file:  `~/Library/Application Support/ioncoin/ioncoin.conf`
Data directory:      `~/Library/Application Support/ioncoin`
Lock file:           `~/Library/Application Support/ioncoin/.lock`

## 4. Installing Service Configuration

### systemd

Installing this .service file consists of just copying it to
/usr/lib/systemd/system directory, followed by the command
`systemctl daemon-reload` in order to update running systemd configuration.

To test, run `systemctl start iond` and to enable for system startup run
`systemctl enable iond`

NOTE: When installing for systemd in Debian/Ubuntu the .service file needs to be copied to the /lib/systemd/system directory instead.

### OpenRC

Rename iond.openrc to iond and drop it in /etc/init.d.  Double
check ownership and permissions and make it executable.  Test it with
`/etc/init.d/iond start` and configure it to run on startup with
`rc-update add iond`

### Upstart (for Debian/Ubuntu based distributions)

Upstart is the default init system for Debian/Ubuntu versions older than 15.04. If you are using version 15.04 or newer and haven't manually configured upstart you should follow the systemd instructions instead.

Drop iond.conf in /etc/init.  Test by running `service iond start`
it will automatically start on reboot.

NOTE: This script is incompatible with CentOS 5 and Amazon Linux 2014 as they
use old versions of Upstart and do not supply the start-stop-daemon utility.

### CentOS

Copy iond.init to /etc/init.d/iond. Test by running `service iond start`.

Using this script, you can adjust the path and flags to the iond program by
setting the IOND and FLAGS environment variables in the file
/etc/sysconfig/iond. You can also use the DAEMONOPTS environment variable here.

### macOS

Copy org.ion.iond.plist into ~/Library/LaunchAgents. Load the launch agent by
running `launchctl load ~/Library/LaunchAgents/org.ion.iond.plist`.

This Launch Agent will cause iond to start whenever the user logs in.

NOTE: This approach is intended for those wanting to run iond as the current user.
You will need to modify org.ion.iond.plist if you intend to use it as a
Launch Daemon with a dedicated ion user.

## 5. Auto-respawn

Auto respawning is currently only configured for Upstart and systemd.
Reasonable defaults have been chosen but YMMV.
