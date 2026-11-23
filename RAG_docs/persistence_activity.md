Fact Sheet: persistence_activity
Script Objective

This detection identifies attempts to make malicious code survive a logout, a reboot, or the removal of the original process, and the mass file operations that characterize ransomware and wipers. The persistence_activity sensor reports two kinds of events: persistence events, emitted when a process writes, renames over, deletes, symlinks, or changes the mode of a file in a location that Linux runs automatically, and mass_file_ops events, emitted when a single process performs a large number of chmod, rename, unlink, or write-open calls within one second.

Persistence is how a RAT, a stealer, a cryptominer, or a backdoor stays resident after its first execution. The common Linux locations are: desktop autostart entries (~/.config/autostart/*.desktop), cron (/etc/crontab, /etc/cron.d/, /etc/cron.hourly, /etc/cron.daily, /var/spool/cron/), systemd units (/etc/systemd/system/, /lib/systemd/system/, and user units in ~/.config/systemd/user/), legacy boot scripts (/etc/rc.local, /etc/init.d/), shell and session startup files (~/.bashrc, ~/.profile, ~/.bash_profile, ~/.xinitrc, ~/.xprofile, /etc/profile.d/), and the dynamic linker preload file /etc/ld.so.preload, which injects a shared library into every dynamically linked process.

The objective of this document is to let the analyst recognize a persistence attempt from the file operation itself, even when the sample is silent on the network and the dropper has already exited, and to recognize bulk file tampering from the per-second counters.

Anomaly Patterns

A persistence event with op open_write, rename, or symlink on a path under /.config/autostart/, by a process that is not a desktop environment tool or a package manager. Typical content is a .desktop file whose Exec line points to a binary in the home directory, /tmp, or a hidden directory. A dropper that copies itself to the home directory and then creates an autostart entry with a name that imitates a system component (for example WIFIADAPTER.desktop) is a strong signature.

A persistence event on /etc/cron.d/, /etc/crontab, /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, or /var/spool/cron/ by an interactive shell, tee, echo redirection, or an unknown binary, especially from a non-root user that obtained root, or a cron entry that runs a script from /tmp, /dev/shm, or a download URL through curl or wget.

A persistence event on /etc/systemd/system/ or /lib/systemd/system/ creating a .service or .timer file, or on ~/.config/systemd/user/, by a process other than systemd, systemctl, or a package manager. A new unit followed by systemctl enable or daemon-reload in suspicious_exec confirms the intent.

A persistence event on /etc/rc.local or /etc/init.d/, where a boot script is appended or created by a shell or an unknown binary.

A persistence event on ~/.bashrc, ~/.profile, ~/.bash_profile, ~/.xinitrc, ~/.xprofile, or /etc/profile.d/ with op open_write by a process other than a shell opened by the owner or a package. Appending a line that launches a hidden binary, sets an alias, or exports LD_PRELOAD is a common technique. Samples that target X sessions, such as Linux.Wirenet, write both ~/.config/autostart and ~/.xinitrc.

A persistence event on /etc/ld.so.preload by any process. The file does not exist on a default installation, so any write is a high-confidence indicator of a userland rootkit or a library injection. Combined with a new .so file written to /lib, /usr/lib, or /tmp, it is almost certainly malicious.

The ops unlink and chmod on the same locations are also reported. A deletion can be the removal of a competing persistence entry or cleanup after the attack, and a chmod +x on a file inside an autostart or init directory completes the installation of a launcher.

A mass_file_ops event, which carries the process name, pid, uid, the operation (chmod, rename, unlink, or open_write), the count n, and a window of 1 second. A count in the hundreds or thousands within one second by one process is the signature of encryption or wiping: Linux ransomware opens each file for writing, rewrites it, and renames it with a new suffix, so open_write and rename counts rise together and are close to each other. A high unlink count together with the same open_write count indicates a wiper or a ransomware that deletes the original after writing the encrypted copy. A very high chmod count by one process indicates permission tampering across a tree, which was observed in ransomware that sets permissions on every file it touches.

The mass_file_ops events repeat once per second while the burst continues, so several consecutive events from the same pid mean a sustained operation, not a single spike. The process name is often a random string or the file name of the dropped binary.

Normal Patterns (Common False Positives)

Package managers and installers (apt, apt-get, dpkg, snap, pip, systemd package hooks) that install unit files into /lib/systemd/system/ or /etc/systemd/system/, create /etc/init.d/ scripts, drop files into /etc/cron.d/ or /etc/profile.d/, and write hundreds of files in one second while unpacking. A dpkg or apt process with a burst of open_write, rename, and unlink is the most common cause of mass_file_ops in a normal system.

Backup and copy tools (tar, rsync, cp, rsnapshot, restic, borg) that extract or restore a tree and produce a large number of open_write, chmod, and rename events during extraction, including permissions restored with chmod. The files keep their original names and the burst ends when the job ends.

Build systems and development tools (make, gcc, npm, cargo, git checkout) that write and remove thousands of small files in a working directory.

Desktop environments, update managers, and configuration tools that create or remove autostart entries on behalf of the user: gnome-session, gnome-tweaks, update-notifier, and applications that offer the option to start at login. Their autostart writes come from a graphical session process with the user uid and a recognizable program name.

Administrators editing ~/.bashrc, ~/.profile, crontab (through crontab -e), or systemd units with an editor (vim, nano), usually with a visible terminal parent and a maintenance reason. The cron daemon also touches its spool directory on its own.

System components that legitimately touch these paths: systemd and systemctl enabling units through symlinks in /etc/systemd/system/ (op symlink by systemctl or systemd), update-rc.d for /etc/init.d/, logrotate and anacron under /etc/cron.*, and the shell reading ~/.bashrc, which does not produce a write event.

The first minutes after a guest boot, when the system itself creates and rotates files, can produce mass_file_ops from journald, tmpfiles, or the package manager, and that noise is stable across runs.

Base Criticality Level

4 (High) – A persistence event outside a package installation or an administrator session indicates that malware already executed and is trying to survive a reboot, and a write to /etc/ld.so.preload deserves 5 (Critical). A single mass_file_ops event from a package manager or a backup tool is low, but a sustained burst from an unknown or randomly named process, with open_write and rename counts in the hundreds or thousands, is 5 (Critical), because encryption of user data is destructive and usually irreversible.

Suggested Correlation

Correlate persistence events with the stage that comes before and after them:

suspicious_exec for the dropper that wrote the entry, the binary it points to running from /tmp, /dev/shm, or the home directory, and for systemctl enable, crontab, or chmod +x after the write.

network_suspicious for the C2 connection or the payload download that happens at the next start. Some RATs persist first and only contact their server after the next login, so the absence of network events does not clear a persistence event.

sensitive_file_access for credential theft by the same process, for instance reads of browser profiles, /etc/shadow, or SSH keys before or after the persistence write.

privilege_escalation for the setuid or capability change that gave a non-root process write access to /etc/cron.d, /etc/systemd/system, or /etc/ld.so.preload.

kernel_module_load and fileless_execution for rootkit components that accompany an ld.so.preload write.

log_tampering and shell history removal after the persistence is installed, used to hide the entry.

For mass_file_ops, correlate with the same pid in suspicious_exec (the binary and its argument, which is often a directory path), with a chmod burst before encryption and a rename burst with a uniform suffix during it, and with the ransom note described in the ransomware fact sheet. A mass_file_ops event whose process name matches an installer or a backup tool and that is not accompanied by suspicious_exec or network indicators should not be escalated on its own. The sensors count operations per process and per second, so a script that runs one new process per file (a shell loop calling touch or chmod) produces no mass_file_ops event.
