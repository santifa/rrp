# rrp (wip)
A collection of RDF parser written in Rust.  

At the moment only the RFC 3986 (URI) is implemented.

## TODO

The main objective for me is to build a set of parsers which are
reliable and fast. I intend to only implement the parser and provide
callbacks to integrate your own data structures into it.  
The main idea behind this is to be as flexible as possible.
In contrast to other implementations which does the heavy lifting
of a full fledge graph, a set of callbacks can provide only the informations
needed discarding unused ones.

[ ] IRI
[ ] N3
[ ] Turtle
[ ] NQuads
[ ] Callbacks
