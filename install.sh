#!/bin/sh
CONFPATH="/etc/netAnalyzer/"
BINPATH="/usr/bin/"

echo "----------------------"
echo "Installing netAnalyzer"
echo "-----------------------"


echo "Installing Configuration in $CONFPATH. Old conf is saved."
install -d $CONFPATH
install -b --suffix=".old" conf/* $CONFPATH

echo "Installing Binary in $BINPATH"
install -d $BINPATH
install netAnalyzer $BINPATH

echo "-----------------------"
echo "Installation Done, you may want to try it: $BINPATH/netAnalyzer"
echo "Quick help can be found by using the -h command"
echo "You may want to visit : http://code.google.com/p/netanalyzer/ for a kick start guide and documentation"
echo "------------------------"