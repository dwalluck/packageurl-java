#!/usr/bin/env bash
JAVA_HOME=$(/usr/libexec/java_home -v 1.8)
PATH="$JAVA_HOME/bin:$PATH"
export JAVA_HOME PATH

read -r -p "Really deploy to Maven Central repository (Y/N)? "
if [ "$REPLY" == "Y" ]; then
  mvn clean
  mvn release:clean release:prepare release:perform -Prelease -X -e | tee release.log
else
  echo -e "Exit without deploy"
fi
