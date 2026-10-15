Fact Sheet: ransomware
Script Objective

This detection identifies the execution phase of Linux and ESXi ransomware: a binary that enumerates a directory tree, encrypts files in place, renames them with a new extension or a randomized name, and drops a ransom note in every directory it touched. The focus is on behavior observed inside the sandbox after the sample runs, not on the delivery vector.

Modern Linux ransomware is built for hypervisors and file servers. Most samples take a single path as a command-line argument and walk it recursively. On VMware ESXi that path is the datastore root (/vmfs/volumes), and the targets are virtual machine files (.vmdk, .vmx, .vmxf, .nvram). On generic Linux hosts the same binaries accept a user directory such as /home, and some walk system paths and SSH keys as well.

The objective of this document is to let the analyst recognize encryption activity from its side effects: the process invocation, the pre-encryption commands that stop virtual machines, the mass rename of files to a new extension, and the ransom note. Ransomware is almost always silent on the network, so the absence of network events must not be read as evidence of a benign process.

Anomaly Patterns

Execution of an unknown or randomly named binary (often 8 random characters, for example ./uswW7SbL or ./ZmfKPLHr) from the current directory, /tmp, or a user-writable path, receiving a single filesystem path as its argument. Observed argument forms: /vmfs/volumes, --path /vmfs/volumes, --encryption_path=/vmfs/volumes, --DIR /home/, or a leading numeric value (thread count) followed by the path.

A shell or the binary itself invoking hypervisor management tools before encryption starts: esxcli vm process list, esxcli vm process kill --type=force --world-id=<id>, pkill -9 vmx-*, vim-cmd vmsvc/getallvms, vim-cmd vmsvc/power.off <id>, vim-cmd vmsvc/snapshot.removeall <id>. The purpose is to release the file locks held by running virtual machines and to delete snapshots that could be used for recovery. Several kill commands in a row, one per world id parsed from the process list, is a strong signature.

Host fingerprinting by the sample right before encryption, such as uname -a combined with hostname run through sh -c, used to build the victim identifier in the ransom note.

A large number of open calls, usually followed by read and write, across many files under a single directory tree in a short period, by a process that is not a backup, archive, or indexing tool. Some samples open thousands of files during enumeration (a few samples issued over seven thousand open calls) and write only to a subset.

Mass rename of files by one process, where each file gains a fixed or randomized suffix appended to the original name, for example .vmdk becoming .vmdk.akira. Observed suffixes include .akira, .avoslinux, .lmario, .puuuk, .buhti, .iFire, .encrptd, .babyk, .itweb, .encrypsss, .C_I_0P, .crypt (preceded by an intermediate .tmp_ name), and per-run random suffixes such as .7rspj or .e8a70B3E9. A suffix that is identical across every renamed file in the same run is a ransomware indicator even when the extension itself is unknown.

Files renamed to a fully random name with a marker extension (for example ._locked or .dragonforce_encrypted) so that the original file name is not recoverable, sometimes with a prefix such as available_for_trial.

Creation of a plain text note with the same name in every traversed directory. Observed names: akira_readme.txt, README_FOR_RESTORE, How To Restore Your Files.txt, HowToRestore.txt, help-readme.txt, Restore-My-Files.txt, readme.txt, how_to_decrypt.txt, README_C_I_0P.TXT, <random>-readme.txt, and Readme.<id>.txt. The note usually sits next to the encrypted files and may be written before encryption completes.

Writes to files with virtual machine extensions (.vmdk, .vmx, .vmxf, .nvram, .vmsd, .vswp, .vmsn) by a process other than the hypervisor itself.

Auxiliary files created in the working directory by the sample, such as a machine or volume identifier (unstable_machine_id, volume_id), a copy of SSH public keys, or an execution arguments file, which some families keep for key management.

Encryption of ordinary Linux paths when the sample is not limited to a datastore: renames under /root/.ssh (id_dsa.pub, id_ed25519.pub), under library directories such as /usr/lib/python3.x, or under /home, which would also break the host.

A single probe write such as sh -c "touch a" before the main loop, used by some samples to check that the target is writable.

No outbound network activity, or a single connect to a hard-coded address with no data exchange, during the whole run. One observed sample opened a socket to a fixed IP and port before encrypting; most observed samples generated no network events at all.

Normal Patterns (Common False Positives)

Backup and synchronization tools (rsync, tar, restic, borg, duplicity, Veeam agents) that read a large number of files in a short time. They read far more than they write, they do not rename files to a new suffix across the tree, and they do not drop notes.

Archive and compression utilities (gzip, zstd, 7z, logrotate) that rename or create files with .gz, .zst, .bz2, .bak, or numeric rotation suffixes. These produce a predictable suffix and keep the original name recoverable.

Package managers, build systems, and editors that create and rename many small files in a working directory (apt, dpkg, pip, make, vim swap files).

Legitimate administrator actions on a hypervisor: esxcli and vim-cmd invoked interactively to list, power off, or snapshot a single virtual machine, with no mass rename of datastore files afterward.

Legitimate use of encryption tools (gpg, openssl, cryptsetup, ecryptfs) on a few user-selected files.

Antivirus, indexing, and file search tools (clamscan, updatedb, find, du) that open every file under a tree but write nothing.

Base Criticality Level

5 (Critical) – Ransomware is destructive and in most cases irreversible once file encryption starts. Hypervisor-targeting variants can take down every virtual machine of a host in minutes, and many operators also exfiltrate data before encrypting it. A confirmed pattern of mass rename with a uniform suffix, a ransom note, or forced termination of virtual machines justifies the highest severity. A single isolated indicator, for example one esxcli call or one rename, is not enough and should be rated lower until the broader pattern appears.

Suggested Correlation

Ransomware is the last stage of an intrusion, so correlate it with the events that usually come before:

suspicious_exec for the dropped binary running from /tmp, /dev/shm, or the current directory, typically after a chmod +x, and for the sh -c invocations of esxcli, vim-cmd, pkill, and uname.

network_suspicious for the download of the payload and, in double-extortion cases, for a large upload to an external address before encryption starts.

sensitive_file_access for reads of SSH keys, credential files, or configuration before the encryption phase.

privilege_escalation for a setuid or capability change shortly before the binary runs as root.

log_tampering and shell history removal after encryption, used to hide the intrusion.

Do not treat the absence of file write, rename, or delete events in the telemetry as proof that no encryption happened: the sensors may not cover those operations. When only the process execution, the virtual machine shutdown commands, or the note creation are visible, describe the encryption as suspected and cite the observed evidence, without stating that files were encrypted or data was exfiltrated.
