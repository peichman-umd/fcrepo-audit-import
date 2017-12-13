fcrepo-audit-import
===========================================

This is a simple script to:

  0. Stream a list of URIs from FCREPO
  1. Get the RDF associated to the URI from FCREPO
  2. POST that RDF to Fuseki 

Usage: 
```
$ java -jar fcrepo-audit-import.jar
```

And select the options.

### Building

This uses both JRuby and some Java libraries. A Maven pom.xml is provides to
pull down the needed java libraries. 
To install everything

```
$ bundle install --binstubs=./bin
$ mvn dependency:copy-dependencies -DoutputDirectory=./lib
$ ./bin/warble
```

This will produce the fcrepo-audit-import.jar file.
