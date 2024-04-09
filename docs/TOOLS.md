# Tools

Chorus comes with four binaries other than the main `chorus` binary.

## chorus_dump

Usage: **chorus_dump** *<path_to_config_file\>*

This dumps every event to STDOUT in JSON format.

## chorus_compress

Usage: **chorus_compress** *<path_to_config_file\>*

This compresses the data by rewriting it entirely.

This leaves the old data under `.bak` extensions (`event.map.bak` and `lmdb.bak`) If these arready exist, the compress command will fail. You are responsible for deleting or saving this files.

## chorus_dump_approvals

Usage: **chorus_dump_approvals** *<path_to_config_file\>*

This shows the public keys you have approved.

## chorus_moderate

Usage: **chorus_moderate** *<path_to_config_file\>*

This is an interactive tool to moderate events which have been accepted, but which are not authored by a chorus user.  If you chose to approve them, they will become available to the public.
