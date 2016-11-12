#!/bin/sh
set -e

loc_="$(readlink -f "$0")"
cd -- "${loc_%/*/*}"

ecryptfs_src_dir_=ecryptfs_src
unpatched_dir_="$ecryptfs_src_dir_"/unpatched
src_dir_=src
patched_dir_="$src_dir_"/ecryptfs_patched
patch_file_="$PWD"/ecryptfs_src.patch

function backup()
{
  mkdir -p bak
  for src_file_ in "$@"
  do
    bak_file_="bak/${src_file_##*/}"
    i_=1
    while [[ -e ${bak_file_}.${i_} ]]
    do
      i_=$(($i_ + 1))
    done
    mv "$src_file_" "$bak_file_.$i_"
  done
}

function display_help()
{
  echo "usage: $0 {extract|get-ordered-options|diff|patch|clean|clean-bak|build|build-debug|chown}"
}

if [[ -z $1 ]]
then
  display_help
  exit
fi

for command_ in "$@"
do
  case $command_ in
    extract)
      # Extract necessary source files from the ecryptfs-utils package.
      mkdir -p -- "$ecryptfs_src_dir_" "$unpatched_dir_"
      pbget ecryptfs-utils
      cd ecryptfs-utils
      makepkg -o
      cd ..
      for file_ in decision_graph.h  #io.c  io.h  mount.ecryptfs.c
      do
        find ecryptfs-utils/src -name "$file_" -exec cp -t "$unpatched_dir_" {} \;
      done
      find ecryptfs-utils/src -name ecryptfs.7 -exec cp -t "$ecryptfs_src_dir_" {} \;
    ;;

    get-ordered-options)
      if [[ -e $ecryptfs_src_dir_/ecryptfs.7 ]]
      then
        # Extract an array of options from the man page.
        echo 'char * ecryptfs_options[] = {'
        while read line_
        do
          if [[ ${line_:0:3} == '.B ' ]]
          then
            option_="${line_:3}"
            option_="${option_%%=*}"
            echo '  "'$option_'",'
          fi
        done < "$ecryptfs_src_dir_"/ecryptfs.7
        echo '};'
      else
        echo "$ecryptfs_src_dir_/ecryptfs.7 does not exist. Run \"$0 extract\" first."
      fi
    ;;

#     diff)
#       if [[ -e $unpatched_dir_ ]]
#       then
#         # Generate the patch file.
#         backup "$patch_file_"
#         TZ=UTC diff -brupN "$unpatched_dir_" "$patched_dir_" > "$patch_file_"
#       else
#         echo "$unpatched_dir_ does not exist. Run \"$0 extract\" first."
#       fi
#     ;;
#
#     patch)
#       # Apply the patch file.
#       rm "$patched_dir_"/* 2>/dev/null || true
#       cp -t "$patched_dir_" "$unpatched_dir_"/*
#       cd -- "$patched_dir_"
#       patch -up2 < "$patch_file_"
#     ;;

    clean)
      # Remove files that should not be included in the source archive.
      rm -fr ecryptfs-utils ecryptfs-simple tmp
      find . \( -name '*.orig' -o -name '*.rej' \) -exec rm {} \+
    ;;

    clean-bak)
      # Remove files that should not be included in the source archive.
      find . -name bak -exec rm -fr {} \+
    ;;

    build)
      # Build the binary.
      gcc -Wall -O2 -o ecryptfs-simple -I "$patched_dir_" \
          -l ecryptfs -l gcrypt -l mount \
          "$src_dir_"/ecryptfs-simple.c
    ;;

    build-debug)
      # Build the binary with debugging turned on.
      gcc -Wall -O2 -o ecryptfs-simple -I "$patched_dir_" \
          -l ecryptfs -l gcrypt -l mount \
          -DDEBUG=1 -finstrument-functions \
          -finstrument-functions-exclude-file-list=include \
          -finstrument-functions-exclude-function-list=main,fprintf,__cyg_profile_func_enter,__cyg_profile_func_exit \
          "$src_dir_"/ecryptfs-simple.c
    ;;

    chown)
      sudo chown root:root ecryptfs-simple
      sudo chmod 4755 ecryptfs-simple
    ;;

    *)
      display_help
    ;;
  esac
done
