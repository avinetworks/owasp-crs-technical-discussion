# Towards a new language for WAF CRS #

* [Goals and Assumptions and Vision](#goals-and-assumptions-and-vision)
  * [Motivation](#motivation)
  * [Assumptions](#assumptions)
  * [Vision](#vision)
* [Whats wrong with the modsec language](#whats-wrong-with-the-modsec-language)
  * [High level](#high-level)
  * [Data Types](#data-types)
  * [Variables](#variables)
  * [Actions](#actions)
  * [language features](#language-features)
  * [language limitations](#language-limitations)
* [Analysis of the current CRS rules](#analysis-of-the-current-crs-rules)
* [Proposal](#proposal)
  * [Overall design vision](#overall-design-vision)
  * [Syntax](#syntax)
  * [Semantic](#semantic)
    * [Data Types](#data-types-1)
    * [Variables and Constants](#variables-and-constants)
    * [Predefined Variables](#predefined-variables)
      * [define a request independent constant](#define-a-request-independent-constant)
      * [extract a value from the request](#extract-a-value-from-the-request)
      * [Modification of variables](#modification-of-variables)
    * [Conditions](#conditions)
    * [Control Flow](#control-flow)
      * [if\-then\-else](#if-then-else)
      * [include](#include)
      * [Actions](#actions-1)
    * [Rules](#rules)
* [Open Questions](#open-questions)

# Goals and Assumptions and Vision #

## Motivation ##

CRS is described in the modsec language.

 - This makes it harder for other (non-modsec) WAFs to adapt CRS. 
 - It makes it hard to maintain these rules in good quality.

Having a more abstracted version which get's compiled down should improve readability.

## Assumptions ##

 - A CRS rule set should be as declarative as possible. Imperative programming style is harder to read, understand and test.
 - The CRS ruleset should be platform independent and should have tools for compilation from the platform independent format to platform specific formats (for example modsec)
 - There is a difference between a WAF config and the CRS. Today, this is mixed as CRS is bound to a single WAF. For example, IP reputation is part of WAF but should not be a part of CRS. 
 - A good WAF should allow 2 kinds of configuration. There should be a declarative part which will solve 95% of all the problems. And a scripting language part which should be good enough to solve all other problems. I see CRS clearly in the declarative config part. A "typical user" should configure their WAF and not program it.

## Vision ##

 - Having a simple to parse, simple to implement declarative language which contains the CRS.
 - Having a compiler from this language into modsec language. The final modsec representation of the CRS should match the current CRS.
 - Having a simple execution model of a WAF in Python which works together with https://github.com/fastly/ftw to check the ruleset.
 - Having compilers from this new language to other WAFs and/or webstacks. For example, having an embedded WAF/CRS interpreter for Java stacks or Django middleware would improve the WAF space and makes CRS a more important player.
 

# Whats wrong with the modsec language #

When we refer to modsec, we mean ["modsec - the language"](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29) which is implemented by "modsec the library" 

## High level ##

 - ModSec (from its history as an Apache Plugin) uses a syntax which is compatible to Apache config files
 - ModSec (from its history as an Apache Plugin) added all extensions from the last 10+ years to be compatible with this original syntax and model and is very confusing for new users. This starts with correct quoting, the different kind of actions, the absent of data types, chain rules, etc.

## Data Types ##

modsec has 2 data types: collections and scalars. A collection is a multi-key dictionary where you can filter for keys and get a smaller collection back. When you iterate over a collection, you get key-value pairs back. There are special collections (ARGS_NAMES for example) where the key is identical to the value.

modsec also includes global (shared between transactions) collections which can be defined on demand.

There is no way to define your own local collection. Instead, rules are using the TX collection and implement a namespace inside this collection with name prefixes. Other rules are implementing lists as a string with delimiters (different rules with different delimiters) because a simple construct like a list of strings is not available. This results in stuff like
```
setvar:'tx.allowed_request_content_type=application/x-www-form-urlencoded|multipart/form-data|text/xml|application/xml|application/soap+xml|application/x-amf|application/json|application/octet-stream|text/plain'"

setvar:'tx.allowed_http_versions=HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0'

setvar:'tx.restricted_extensions=.asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .resources/ .resx/ .sql/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/'"
```

There is no difference between a `string` and an `int` in modsec.
But there are different comparison operators which generate problems.
This should be detected and/or the right operator should be clear from the context. If we need a `string` as an `int` (for example the value of the Content-Lenght header, we should have to express this explicitly.

## Variables ##

There is more or less one flat variable name space, the TX collection.

## Actions ##

modsec is using "actions" for a couple of different things.

 - static attributes like 
   - id
   - severity
   - version, revision
   - execution phase
   - accuracy, maturity
 - grouping: tags
 - actions: block, deny, pass, allow, ...
 - update variables / state modifications: setvar. Used for
   - temporary variables
   - control flow
   - anomaly mode handling
   - correlation between rules (phase 5)
 - control flow: skipAfter, removeTargetById
 - logging (what should be logged)
 - chain
   - to combine rules
 
## language features ##

modsec defines PCRE as the regex engine and may construct problems with other engines like python re or Google re2

modsec is using some special operators like verifyCC or similar for features which should be implemented as a regex and a validation function.

## language limitations ##

For some cases, there are special operators, like verifyCC. Some things can not be implemented, like validation of range header - CRS rule 920190. It is not possible to write a rule which will:
 - extract multiple parts from a variables
 - verify every single part in a second rule

# Analysis of the current CRS rules #

Some things are out of scope for this document. They are part of WAF but not necessary part of CRS. For example:

 - Sampling
 - IP reputation
 - Anomaly detection over time from the same IP / Session
 - Log correlation
 - ...

# Proposal #

## Overall design vision ##

 - fully declarative (single assignment)
 - Vendor independent - should be a community project and part of CRS.
 

## Syntax ##

I have a very strong opinion on how a good syntax should look like, but I think this should be discussed later. 

To avoid discussions here, I'm using YAML as syntax. 

You may find pieces of proposals of alternative syntax inline, please do not discuss this except when you love it ;-)

## Semantic ##

### Data Types ###

The should exist the following scalar data types:

 - string
 - int
 - regex
 - bool (?)
 - score (?)
   - used for automatic score counting. Does have a max value and an action attached.
   - needs a little more investigation .....
 
Compound types:

 - list of (strings, int, regex)
 - collection string -> scalar
 
Operations on these types

 - convert:
   - int("42") -> 42
 - length(string) -> int # see transformations below
 - length(list) -> int
 - names(collection) -> [string]
 - group(string list) -> collection of element from the list and the number of their occurence
 
 - transformation -> every useful transformation from string -> string or int which is used in CRS
 
 - ?? extract variable regex part (`extract REQUEST_HEADERS:Content-Type /^([^\s;]*/ $i`)


### Variables and Constants ###

### Predefined Variables ###

All variables which exist in modsec which describe a part of the request do exist with the same name here for pragmatic reasons. We may rename them later. 

#### define a request independent constant ####


```.yaml
- define:
    name: max_body_size
    type: int
    value: 32k

- define:
    name: restricted_extensions
    type: [string]
    value:
        - "asa"
        - "asax"
        - ...
        - "xsd"
        - "xsx"
    transformation:
        - ".%{$1}"    

- define: 
    - name: unix_shell_data
    - type: [string]
    - load: "unix-shell.data"
```

Note that the types are redundant here, because they can be derived from the context.

#### extract a value from the request ####

We need a way to extract more data from the request if the underlying WAF does not already have this variable.

```.yaml
- define:
    comment: extract the request extension, first chain from 912150
    name: request_basename_extension
    type: string
    extract:
        variable: REQUEST_BASENAME
        pattern: /(\.[a-z0-9]{1,10})?$/
        value: $1
```

If the variable is not defined, the new variable is not defined. A
rule will not execute on this variables (same as for pre-defined
variables which does not exist, for example REQUEST_HEADER:foo)

#### Modification of variables ####

In an ideal world, we should *never* modify a variable. So we should treat them as constants. 
But for some special cases in the application specific exclusion handling, we are adding 2 operators which are working on lists: `add-to-list` and `remove-from-list`.
To contain the declarative behaviour, it is not allowed to have the same string in an `add-to-list` and `remove-from-list` for the same list. Which means that the order of the add/remove ops are not relevant and it is still declarative in some sense.

```.yaml
- add-to-list:
    variable: allowed_request_content_type
    elements:
        - "application/special-content-type"
        
- remove-from-list:
    variable: allowed_request_content_type
    elements:
        - "text/xml"
        - "application/xml"
        - "application/soap+xml"
```

### Conditions ###

Conditions are more or less the same as modsec variables + operators

```.yaml
- condition:
    - comment: check if the extension of the request is in the list of restricted extensions
      variables:
          - request_basename_extension
      transformations:
          - lowercase
      operator: in
      parameter: restricted_extensions

- condition:
    - variables:
          - ARGS
          - REQUEST_HEADERS
      operator: rx
      parameter: /script>/
```

As variables, all predefined variables and all defined variables
can be used here. It is an error when the compiler can not determine
that a variable is declared here (e.g. if you declare a variable
in an if block)

There are additional operators for new data types:

 - *var* in *list*
 - *var* == *element*
 - *var* ~ *regex*
 - *var* exists
 	- is defined and not nil

There are also special variables $0 ... $9 which can be used if the
operator in the preceding condition was rx. These variables are
then interpreted like a capture in the current modsec ruleset.
> Not sure if this is needed, this can be probably avoided with the definition of new variables with extract data from a request.

      

### Control Flow ###

#### if-then-else ####

To allow optional rules (think of skip rules in modsec or flags which are checked in every chain rule)

In the `then` and `else` block can contain anything which is allowed on the toplevel, e.g. "define", "rule", "if" and "include"

The `else` part is optional

```.yaml
- if:
    conditions:
        - condition 1
        - condition 2
    then:
        - define
        - rule
        - rule
    else:
        - define
```


#### include ####

To allow modularisation, we should allow an include directive

```.yaml
- include: name-of-file
- include:
  - file-name-1
  - file-name-2
```

#### Actions ####

The following list of actions can be executed, either in `global`, in an `if` block or in the action part of of a rule.

 - default
 - deny
 - disable-rule (by id, by id-range, by tag)
 - remove-variable-from-rule
 - allow
 
```.yaml
- actions:
    - disable-rule: 12345
    - remove-variable-from-rule:
        variable: ARGS:password
        rules: 1-9999999
- actions:
    - block

- actions:
    - block:
        comment: do we really need to be this specific here?
        reason: Content-Length header is required.
        code: 411

```


Note that there is no setvar here, because I think it is not needed. All the anomaly scoring stuff can be done by the compiler, names and valued can be derived from the severity, phase and paranoia level.

### Rules ###

So a rule is more or less the same as an `if/then/else` construct with some meta data attached.


The simple form

```.yaml
- rule:
    id: 999999
    meta:
        phase: request  # not sure if we need this
        message: "Possible Foo attacks"
        paranoia-level: 1
        severity: CRITICAL # also be used to determine anomaly value
        version: 1
        # ...
        tags:
            - "application-multi"
    conditions:
        - variable: 
            - ARGS
          transformations:
             - removeSpaces  
          operator: rx
          paramater: /some crazy regex/  
    actions:
        - block  
```          

is a shortcut for the complete form, which contains and else bloc (and therefore need the if too.

```.yaml
- rule:
    id: 999999
    meta:
        phase: request  # not sure if we need this
        message: "Possible Foo attacks"
        paranoia-level: 1
        severity: CRITICAL # also be used to determine anomaly value
        version: 1
        # ...
        tags:
            - "application-multi"
    if:
            conditions:
                - variable:
                    - ARGS
                  transformations:
                     - removeSpaces
                  operator: rx
                  paramater: /some crazy regex/
    then:
        actions:
            - block
    else:
        comment: not needed here
```

We can probably shortcut this to allow then/else have an explicit actions part. This will allow stuff like a positiv security model:

```.yaml
- rule:
    id: 42
    comment: make sure that all the cookie values contain only hex characters
    if:
        conditions:
            - variables:
                - REQUEST_COOKIE
              operator: rx
              parameter /^[a-fA-F0-9]+$/
    then:
        comment: match, everything is ok. Mark die variable as fine for all other rules
        action:
            - whitelist MATCHED_VARS
    else:
        - block
```

Note that this probably need more refinement, because we can have multiple vars with the same name.
    

# Open Questions #

## Positive Security model ##

Do we want to include a positive security model? The current implementation of application specific stuff by disabling some rules for some parameters is more a simple false positive handling. We should be able to declare something like:

> if the Wordpress flag is set, and the URL starts with admin, the ARGS:password parameter should match ^.{0,32}$. If not, the request should be rejected. if yes, do not bother to check "ARGS:password" on any other rule at all, it is ok.  
          
## Test ##

Tests should be a first class objects when describing a ruleset.

Which means, for every condition it should be possible to add a
list of values which should match and not match. A rule validator
should run these tests. A compiler should run these tests during
compilation and abort when they are failing.

Need a syntax for this.

      



