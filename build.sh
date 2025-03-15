#!/bin/bash
set -ex

PANDOC_OPT="-f markdown --standalone --highlight-style=tango"

# HACK HACK HACK, relies on input markdown format!
# - Strip the title line (will be re-added by Pandoc from mandatory metadata)
# - Replace the top URL header with a table, including right-aligned "back" link
tweakMarkdown() {
    cat $1 \
        | tail -n +3 \
        | sed -r '1s|(.*)|<table class="header_bar"><tr class="header_bar"><td class="header_bar"> \1 </td><td class="header_bar" align="right"> [Back to index](../../) </td></tr></table> \n\n<hr>|'
}

# Buildable on local machine too
test "$1" == "git" && BUILD_DIR=build || BUILD_DIR=$HOME/public_html/mufl0n.github.io

# Prepare the build directory and copy the repo
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
cp -R README.md favicon.ico shc $BUILD_DIR
cd $BUILD_DIR

# Render the placeholder site index page
pandoc $PANDOC_OPT \
    --css=shc/resources/markdown.css \
    --output=index.html \
    --metadata title="mufl0n.github.io" \
    <(tail -n +2 README.md)

# Render the SHC library index page
pandoc $PANDOC_OPT \
    --css=resources/markdown.css \
    --output=shc/index.html \
    --metadata title="SHC Library write-ups" \
    <(tail -n +2 shc/README.md)

# Render all the write-ups
for CHALL in shc/*/*/README.md;
do
    DIR="${CHALL%/*}"
    NAME="${DIR##*/}"
    if [ "$1" == "git" ];
    then
        # If running on GitHub, process files sequentially
        pandoc $PANDOC_OPT  \
            --css=../../../shc/resources/markdown.css \
            --output=$DIR/index.html \
            --metadata title="$NAME" \
            <(tweakMarkdown $CHALL)
    else
        # If running on local system, procees all files in parallel
        pandoc $PANDOC_OPT  \
            --css=../../../shc/resources/markdown.css \
            --output=$DIR/index.html \
            --metadata title="$NAME" \
            <(tweakMarkdown $CHALL) &
    fi
done
test "$1" != "git" ] && wait || true

# Cleanup markdown files from the build directory
rm -f README.md shc/README.md shc/*/*/README.md
