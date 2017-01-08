# Docker, Python, and You

## Build

Builds the image, after this it's immutable in the current form:

    $ docker build -t myapp .

Note, there is an implicit tag of `latest`.

## Run

Runs the image (making a container), since docker does network isolation you
need to explicitly list the exposed port(s):

    $ docker run --rm -it -p 5000:5000 myapp

