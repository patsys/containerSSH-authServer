#!/bin/sh
if [ "$PRE_SCRIPT" ]; then
  script=$(mktemp /tmp/pre_script.XXXXXX)
  echo -n " $PRE_SCRIPT" >$script
  chmod ugo+x $script
  $script
fi
/bin/authServer $@
