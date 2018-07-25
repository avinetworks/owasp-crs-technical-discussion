# Towards a new language for WAF CRS #

# Goals and Assumptions and Vision #

## Motivation ##

CRS is described in the ModSec language.

 - This makes it harder for other (non-modsec) WAFs to adapt CRS. 
 - It makes it hard to maintain these rules in good quality.

Having a more abstracted version which get's compiled down should improve readability.

## Assumptions ##

 - A CRS rule set should be as declarative as possible. Imperative programming style is harder to read, understand and test.
 - The CRS ruleset should be platform independent and should have tools for compilation from the platform independent format to platform specific formats (for example ModSec)
 - There is a difference between a WAF config and the CRS. Today, this is mixed, as CRS is bound to a single WAF. For example, IP reputation is part of WAF but should not be a part of CRS. 
 - A good WAF should allow 2 kinds of configuration. There should be a declarative part which will be sufficient for 95% of all users. And a scripting language part which should be good enough to solve all the special needs of the remaining users. I see CRS clearly in the declarative config part. A "typical user" should configure their WAF and not program it.
 - The CRS rule description should allow positive and negative security problem

## Vision ##

 - Having a simple to parse, simple to implement declarative language which is just powerful enough to express the CRS.
 - Having a compiler from this language into ModSec language. The final ModSec representation of the CRS should match the current CRS.
 - Having a simple execution model of a WAF in Python which works together with https://github.com/fastly/ftw to check the ruleset.
 - Having compilers from this new language to other WAFs and/or webstacks. For example, having an embedded WAF/CRS interpreter for Java stacks or Django middleware would improve the WAF space and makes CRS a more important player.
 - This language should support an positive security model. 
 - Integrate with vulnerability tools like Threadfix which can generate WAF rules from vulnerability findings
 
## Definitions ##

### Negative Security Model ###

The classical model where the rule tries to detect known attack patterns. If a known attack is detected, the request is flagged as bad.

### Positive Security Model ###

A model where the rule describes how a variable (a specific part of the request) should look like.

This comes in 2 flavours. A rule can be "required" and/or "sufficient". 

 - "required" means, when the input does not conform to the rule, the request will be flagged as bad.   
 - "sufficient" means, when the input does conform to the rule, that then no other rule (from the positive or the negative security model) will be checked on this part of the request (for example this argument).
 
### Exclusions ###

Exclusions (or Exceptions) are used to adapt a generic rule to a local installation. It declares, the this (generic) rule should not be applied to this specific variable.


# Language Proposal #

## Overall design vision ##

 - fully declarative (single assignment)
 - Vendor independent - should be a community project and part of CRS.
 
## Overall design constraints ##

We still need rule-id's for manageability pf the CRS.

## Syntax ##

I have a very strong opinion on how a good syntax for a WAF should look like, but I think this should be discussed later and independent of this proposal. 

As a "lingua franca", the language should use an universal data exchange format for it's syntax. 

I'm using YAML as syntax, JSON and XML would be fine too, but I think YAML is easier to read for a human.

## Semantic ##

### Data Types ###

The following scalar data types should be supported

 - string
 - int
 - regex
 - bool

Compound types:

 - list of (strings, int, regex)
 - collection string -> scalar (multi value like ModSec)
 
Operations on these types

 - convert:
   - int("42") -> 42
   
 - length(string) -> int # see transformations below
 - length(list) -> int
 - names(collection) -> [string]
 - group(string list) -> collection of element from the list and the number of their occurence
 
 - transformation -> every useful transformation from string -> string or int which is used in CRS
 

Note that we have a separate type for regex and we also allow a list of regex here. Both can be used as a parameter of the `@rx` or similar operators. A list of regex is here equivalent to an `|` concatenation of all the regexes in the list. This would allow to write these large and ugly regexes actually in a more readable form and let the compiler do the optimisation if necessary.

### Variables and Constants ###
.
### Predefined Variables ###

All variables which exist in modsec which describe a part of the request do exist with the sameor similar name here for pragmatic reasons. We may rename them later. 

What is open here, is a clear definition what the variable means, e.g. it is already urldecoded or not.

#### define a request independent constant ####


Define a constant "max_body_size" as an integer with the value of 32k (32768)

```.yaml
- define:
    name: max_body_size
    type: int
    value: 32k
```

Define "restricted_extensions" as a list of strings. The final transformation is optional and I'm not sure if it is needed. But it can be used to `map` the list.

```.yaml
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
        - ".%{$0}"   
``` 

Define `unix_shell_data` as a list of strings, and load the actual value from an external resource.

```.yaml
- define: 
    - name: unix_shell_data
    - type: [string]
    - load: "unix-shell.data"
```
Note that the types are redundant here, because they can be derived from the syntax. But I think it is good to require explicit typing.

If you do not add a value here, this is only a declaration. This introduced the variable but set the value to `unset` with is represented by `null`. This value is special and we will explain later how variables with the value are handled in conditions in rules and control flow.


#### extract a value from the request ####

We need a way to extract  data from the request if the underlying WAF does not already have this variable. Here we are using the define together with an `extract` statement

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
variables which does not exist, for example REQUEST_HEADER:foo).

Not sure if we should allow operations on lists or collections here or if variable should always be a scalar.

#### Modification of variables ####

In an ideal world, we should *never* modify a variable. So we should treat them as constants. 
But for some special cases in the application specific exclusion handling, we are adding 2 operators which are working on lists: `add-to-list` and `remove-from-list`.
To keep the declarative behaviour, it is not allowed to have the same string in an `add-to-list` and `remove-from-list` for the same list. Which means that the order of the add/remove ops are not relevant and it is still declarative in some sense.

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
      parameter: $(restricted_extensions)

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
in an if block but not in an else block.

FIXME: there may be a problem here with bool and set-one semantic. Think about it later.

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

We have to distinguish 2 different conditions here. One are preconditions which need to be met to trigger the rule. For example, we only want to trigger the rule when we have a given content type header.

This can be done either by an explicit `if/then/else` around the rule or we can add a `precondition` part to the rule. The second solution is probably nicer to read.

The second condition is the check for the actual attack. Note that whenever you are setting exclusion for rules (remove-variable-from-rule), you are removing the variables from this second part.

The action block does usually contain 

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
    preconditions:
        - variable: REQUEST_METHOD
          operator: @streq
          parameter: "POST"
        - variable: basename_extension
          operator: @streq
          parameter: "foo"
    if:
        variable: 
            - ARGS
        transformations:
             - removeSpaces  
        operator: rx
        parameter: /some crazy regex/
    then:
        - block  
         
```                  

### rule templates ###

Not sure if needed. But there may be a usecase for a simple form of single inheritance for rules, to avoid repetitive typing:

Defining a template for a rule:

```.yaml
- template:
    name: name-of-template
    rule:
```

Using a template for a rule:

```.yaml
- rule:
    id: 123456
    template: name-of-template
    check:
       ...
```

In this case, rule is created by cloning the rule from the template and updating all fields which are set in the rule itself. lists are overwritten, objects will be updated.

A rule in a template can inherit from another template.


# Open Questions #

## Positive Security model ##

Do we want to include a positive security model? The current implementation of application specific stuff by disabling some rules for some parameters is more a simple false positive handling. We should be able to declare something like:

> if the Wordpress flag is set, and the URL starts with admin, the ARGS:password parameter should match `^.{0,32}$`. If not, the request should be rejected. if yes, do not bother to check "ARGS:password" on any other rule at all, it is ok.  

I would like to include it in the above rule format

```.yaml
- rule:
  id:
  meta:
  preconditions:
  if:
      variable:
          - ARGS
      operator: @rx
      parameter: /^[0-9]$/
  then:
      - whitelist
  else:
      - block    
```
          
## Test ##

Tests should be a first class objects when describing a ruleset.

Which means, for every condition it should be possible to add a
list of values which should match and not match. A rule validator
should run these tests. A compiler should run these tests during
compilation and abort when they are failing.

Need a syntax for this.

      


