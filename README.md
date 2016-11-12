# ecryptfs-simple
a github fork of ecryptfs-simple project located at: http://xyne.archlinux.ca/projects/ecryptfs-simple/

Improvements:

0. Have the project hosted at github.

1. Uses cmake as a build system.

2. A bit of code clean up since it now compiles without warnings while using strict compile options.

3. Fix a bug that causes volumes config path to be at "~/config/.ecryptfs-simple"
   instead of at "~/config/ecryptfs-simple"

4. Make the project work while not started from the terminal.

