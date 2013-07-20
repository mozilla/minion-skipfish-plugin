Minion Skipfish Plugin
======================

This is a plugin for Minion that executes the Skipfish tool. It assumes Skipfish is installed on your system and that is is on the system PATH. It also expects Skipfish dictionaries to be installed in `/usr/share/skipfish/dictionaries`.

Whatever platform you use, you will need the following tools:

* Python 2.7
* virtualenv

For skipfish itself:

* skipfish >= 2.10b

If you work on Ubuntu 13.04 or above:

    $ sudo apt-get install skipfish
    
If you work on Ubuntu older than 13.04:

    wget http://launchpadlibrarian.net/126324292/skipfish_2.10b-1_i386.deb     (for 32-bit)
    wget http://launchpadlibrarian.net/126324272/skipfish_2.10b-1_amd64.deb    (for 64-bit)
    sudo dpkg -i skipfish_2.10b-1_[i368|am64].deb

You should search ``skipfish`` on your operating system's source package manager. For example, Fedora should have the latest
skipfish via ``yum``.
