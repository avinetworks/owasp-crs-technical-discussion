Towards a new language for WAF CRS
==================================

  * [Motivation](#motivation)
  * [Assumptions](#assumptions)
  * [Overall Vision](#overall-vision)
  * [Definitions](#definitions)
     * [Negative Security Model](#negative-security-model)
     * [Positive Security Model](#positive-security-model)
     * [Exclusions](#exclusions)
  * [Overall design vision](#overall-design-vision)
  * [Overall design constraints](#overall-design-constraints)
  * [Syntax](#syntax)
  * [Semantic](#semantic)
     * [Data Types](#data-types)
     * [Variables and Constants](#variables-and-constants)
     * [Predefined Variables](#predefined-variables)
        * [define a request independent constant](#define-a-request-independent-constant)
        * [extract a value from the request](#extract-a-value-from-the-request)
        * [Modification of variables](#modification-of-variables)
     * [Conditions](#conditions)
     * [Control Flow](#control-flow)
        * [if-then-else](#if-then-else)
        * [include](#include)
        * [Actions](#actions)
     * [Rules](#rules)
        * [classic negative security model](#classic-negative-security-model)
        * [positive security model](#positive-security-model-1)
     * [rule templates](#rule-templates)
  * [Examples](#examples)
     * [Multiple extraction steps](#multiple-extraction-steps)
     * [Accessing the same variable multiple times](#accessing-the-same-variable-multiple-times)
     * [Example from PR 4](#example-from-pr-4)

## Motivation ##

CRS is described in the ModSecurity language.

 - This makes it harder for other (non-ModSecurity) WAFs to adapt CRS. 
 - It makes it hard to maintain these rules in good quality.

Having a more abstracted version which get's compiled down should improve readability.

## Assumptions ##

 - A CRS rule set should be as declarative as possible. Imperative programming style is harder to read, understand and test.
 - The CRS ruleset should be platform independent and should have tools for compilation from the platform independent format to platform specific formats (for example ModSec)
 - There is a difference between a WAF config and the CRS. Today, this is mixed, as CRS is bound to a single WAF. For example, IP reputation is part of WAF but should not be a part of CRS. 
 - A good WAF should allow 2 kinds of configuration. There should be a declarative part which will be sufficient for 95% of all users. And a scripting language part which should be good enough to solve all the special needs of the remaining users. I see CRS clearly in the declarative config part. A "typical user" should configure their WAF and not program it.
 - The CRS rule description should allow positive and negative security problem

## Overall Vision ##

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


## Overall design vision ##

 - fully declarative (single assignment)
 - Vendor independent - should be a community project and part of CRS.
 
## Overall design constraints ##

We still need rule-id's for manageability of the CRS.

We need to be able to translate all the rules to ModSecurity and other WAF's rule language. This means that some features can not be expressed. An example for a feature which can not be expressed is a proper check of the Request-Range header which CRS rule 920190 is trying to achieve.

For features like the positive security model, we need a way to mark the value of a variable as not to be checked by upcoming rules. ModSecurity does have the "removeTargetById" feature which does basically this. But doing it right in ModSecurity is hard, because there is no clear distinction between variables which are used for control flow and variables which are used to check for attacks. A good example here is the REQUEST_HEADERS:Content-Type. It is used in control flow (for deciding which body processor to use) and can also be the place to detect attacks. A rule language should distinguish these 2 kinds of usage.

## Syntax ##

Different people have different opinions about good syntax. But the more important point is the semantic, so we will drop the discussion of the syntax for now.

As a "lingua franca" the language should use a universal data exchange format for it's syntax. 

I'm using [YAML](http://yaml.org) as syntax, JSON and XML would be fine too, but I think YAML is easier to read (while harder to write than JSON) for a human.

We describe the language here in it's full canonical form. On some places, things can be omitted and abbreviated to make it more readable. 


## Semantic ##

### Data Types ###

The following scalar data types should be supported

 - string
 - int
 - regex
 - bool

Compound types:

 - list of (strings, int, regex)
 - collection string -> scalar (multi value like ModSec). I'm not sure if we need this now, but wee keep
 
Operations on these types

 - convert:
   - int("42") -> 42
   
 - length(string) -> int # see transformations below
 - length(list) -> int
 - names(collection) -> [string]
 - group(string list) -> collection of element from the list and the number of their occurrence
 
 - transformation -> every useful transformation from string -> string or int which is used in CRS
 

Note that we have a separate type for regex and we also allow a list of regex here. Both can be used as a parameter of the `@rx` or similar operators. A list of regex is here equivalent to an `|` concatenation of all the regexes in the list. This would allow to write these large and ugly regexes actually in a more readable form and let the compiler do the optimisation if necessary.

### Variables and Constants ###

### Predefined Variables ###

All variables which exist in ModSecurity which describe a part of the request do exist with the same or similar name here for pragmatic reasons. We may rename them later. 

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

We need a way to extract  data from the request if the underlying WAF does not already have this variable. Here we are using the `define` together with an `extract` statement

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
variables which does not exist, for example `REQUEST_HEADER:foo`).

Not sure if we should allow operations on lists or collections here or if variable should always be a scalar.

#### Modification of variables ####

In an ideal world, we should *never* modify a variable. So we should treat them as constants. 
But for some special cases in the application specific exclusion handling, we are adding 2 operators which are working on lists: `add-to-list` and `remove-from-list`.
To keep the declarative behaviour, it is not allowed to have the same string in an `add-to-list` and `remove-from-list` for the same list. Which means that the order of the add/remove ops are not relevant and it is still declarative in some sense.

FIXME: I still looking for a better name for these 2 modifies which make the declarative behaviour more clear. Something along the lines of "ensure-in-list" and "ensure-not-in-list"

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

There are 3 different kind of conditions in this language. They all describe the same concept (a boolean expression) but these are used in 3 different contexts.

The first context is control flow. The result of the evaluation of the conditions decides, if a block of code is active for this request. This condition is part of an if/then/else control flow.

The second context is similar to the first, this are preconditions for rules. These conditions decide, if a rule should be executed. This condition is part of the if block inside a rule.

The third is fundamental different. This is the conditions where the rule is checking for an attack in some variable. Like checking if the string `</` is part of the user input. This is part of the "detect" part of the rule.

While these 3 conditions are formally interchangeable (you can always move the "detect" part to the precondition of the rule and use an "always match" operator for the "detect" part), we are making them  different here to explicitly distinguish between control flow an attack detection. This is important when we using "remove-target-from-rule" or positive security model rule interact in a sane way with rules. 

Also, we restrict the "detect" context to having only one condition (or multiple conditions on the same variable(s))


All 3 conditions are more or less the same as ModSecurity variables + operators

```.yaml
- detect:
     comment: check if the extension of the request is in the list of restricted extensions
      variables:
          - request_basename_extension
      transformations:
          - lowercase
      operator: in
      parameter: $(restricted_extensions)

- detect:
      variables:
          - ARGS
          - REQUEST_HEADERS
      exclude:
          - ARGS:editor_input_field
      operator: rx
      parameter: /script>/

```

All predefined variables (like `ARGS` and `REQUEST_HEADER:Content-Length`) and all user defined variables
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
      

### Control Flow ###

#### if-then-else ####

To allow optional rules (think of skip rules in ModSecurity or flags which are checked in every chain rule)

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

#### classic negative security model ###

A rule contains of meta data, optional preconditions and detect rule. I removed the actions here, because they are probably not needed and is always block - depended on the severity is may also only be log - but this is not part of the rule knowledge but part of the environment and the compiler

```.yaml
- rule:
    id: 999999
    meta:
        phase: request  # not sure if we need this
        message: "Possible Foo attacks"
        paranoia-level: 1
        severity: CRITICAL # also used to determine anomaly value
        version: 1
        # ...
        tags:
            - "application-multi"
    preconditions:
        - variable: REQUEST_METHOD
          operator: streq
          parameter: "POST"
        - variable: basename_extension
          operator: streq
          parameter: "foo"
    detect:
        variables: 
            - ARGS
        transformations:
             - removeSpaces
        checks:
            - operator: rx
              parameter: /some crazy regex/
     
```  

Note that "checks" is a list of multiple conditions on these variables. The conditions must all be true to match a variable. In most rules, we will only have one condition. In this case, as a shortcut, "checks" can be omitted and operator and parameter can be moved up one level in the structure.

#### positive security model ####

The rules are looking the same as above. Instead of "detect" we are using "ensure" to define how a variable should look like. As mentioned in the beginning, positive security rules can be "required", "sufficient" or both. If they are "required" and a variable does not match, this counts as "detecting an attack". If the rule is sufficient and a variable match, this means that this variable will not be checked by following rule, especially by the classical negative security model rules. To make the rule order still declarative, the compiler will warn you if the result is oder depended. From a performance point of view, we prefer to execute all positive security model rules before the negative security model rules and execute the sufficient rules before the required rules.

```.yaml
- rule:
    id: 42
    meta:
    comment: 
        - We do not care about __utm request cookie in the following rules, as long
        - as it is not bigger than 4k. We will reject a request with an __utm cookie
        - larger than 4k
    ensure:
        variables:
            - REQUEST_COOKIES:__utm
        checks:
            - operator: length
              parameter: 4k
        mode:
            - sufficient
            - required
  

- rule: 
    id: 23
    meta:
    comment: a product id is used a direct database reference. It must be a number.
    ensure:
        variables:
            - ARGS:product_id   
        checks:
            - operator: rx
              parameter: /^\d{1,20}$/
        mode:
            - required
            - sufficient
            
- rule:
    id: 34
    meta:
    comment: input field foo is base64 encoded stuff
    ensure:
        variables:
            - ARGS:foo
        checks:
            - operator: rx  
              parameter: /^[0-9a-zA-Z+/]+=?=?$/
        mode:
            - requried

```
          
### rule templates ###

This is probably not needed, just an idea. I'm not sure if this will simplify rule writing and understanding.

But there may be a use case for a simple form of single inheritance for rules, to avoid repetitive typing:

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
    detect:
       ...
```

In this case, rule is created by cloning the rule from the template and updating all fields which are set in the rule itself. lists are overwritten, objects will be updated.

A rule in a template can inherit from another template.

## Examples ##

This sections contain examples on how to express some more complicated ModSecurity rules in the new language:


### Multiple extraction steps ###

Interesting rule from https://github.com/SpiderLabs/ModSecurity/issues/1632

```
#example from https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#base64decode
SecRule REQUEST_HEADERS:Authorization "^Basic ([a-zA-Z0-9]+=*)$" "phase:1,id:93,capture,chain,logdata:%{TX.1}"
  SecRule TX:1 ^(\w+): t:base64Decode,capture,chain
    SecRule TX:1 ^(admin|root|backup)$ 
```

```.yaml
- define:
    name: basic_auth_header
    type: string
    extract:
        variable: REQUEST_HEADERS:Authorization
        pattern: /^Basic\s+([a-zA-Z0-9]+=*)$/
        value: $1
        
- define:
    name: basic_auth_header_username
    type: string
    extract:
        variable: basic_auth_header
        transformation: base64decode
        pattern: /^([^:]+):/
        value: $1
        
- define:
    name: invalid_basic_auth_usernames
    type: [string]
    value:
        - admin
        - root
        - backup     

- rule:
    ...
    condition:
        variable: basic_auth_header_username
        operator: in
        value: $invalid_basic_auth_usernames
```

### Accessing the same variable multiple times ###

See rule 942150

```
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@pmf sql-function-names.data" \
    "id:942150,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:lowercase,\
    msg:'SQL Injection Attack',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
    tag:'WASCTC/WASC-19',\
    tag:'OWASP_TOP_10/A1',\
    tag:'OWASP_AppSensor/CIE1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/2',\
    ctl:auditLogParts=+E,\
    rev:2,\
    ver:'OWASP_CRS/3.0.0',\
    severity:'CRITICAL',\
    chain"
    SecRule MATCHED_VARS "@rx (?i)\b(?:c(?:o(?:n(?:v(?:ert(?:_tz)?)?|c....
        "setvar:'tx.msg=%{rule.msg}',\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/SQL_INJECTION-%{matched_var_name}=%{tx.0}'"
```

Can be translated to

```.yaml
- define:
    name: sql_function_names
    type: [string]
    load: "sql-function-name.data"
    
- define:
    name: sql_function_names_regex
    type: regex
    value: /(?i)\b(?:c(?:o(?:n(?:v(?:ert(?:_tz)?)?|c.......    
- rule:
    id: 942150
    meta:
        ....
    detect:
        variables: 
            - REQUEST_COOKIES
            - REQUEST_COOKIES_NAMES
            - ARGS_NAMES
            - ARGS
            - XML:/* 
        exclude:
            - REQUEST_COOKIES:/__utm/
        checks:
            - operator: pm
              parameter: ${sql_function_name}
            - operator: rx
              parameter: ${sql_function_names_regex}
```    


### Example from PR 4  ###

```.yaml

- rule:
    id: 920100
    comment: Check HTTP/1.1 request line for correctness
    meta:
        name: HTTP/1.1 Request line
        message: "Invalid HTTP Request Line"
        strategy: whitelist
        paranoia-level: 1
        version: OWASP_CRS/3.1.0
        tags:
            - CAPEC:
                - 272
    ensure:
        variables:
            - REQUEST_LINE
        transformations:
            - lowercase
        checks:
            - operator: rx
              parameter:
                  - /^(?i:(?:[a-z]{3,10}\s+(?:\w{3,7}?:\/\/[\w\-\.\/]*(?::\d+)?)?\/[^?#]*(?:\?[^#\s]*)?(?:#[\S]*)?)?)$/
                  - /^(?i:(?:connect (?:\d{1,3}\.){3}\d{1,3}\.?(?::\d+)?)?)$/
                  - /^(?i:get \/[^?#]*(?:\?[^#\s]*)?(?:#[\S]*)?)$/
        mode:
            - required


- rule:
    id: 920120
    comment: Block Filenames with out of place metachars
    meta:
        name: HTTP/1.1 Request line
        strategy: blacklist
        message: "Attempted multipart/form-data bypass"
        paranoia-level: 1
        version: OWASP_CRS/3.1.0
        tags:
            - CAPEC:
                - 272
    detect:
        variables:
            - REQUEST_LINE
        transformations:
            - htmlEntityDecode
            - lowercase
        checks:
            - operator: rx
              parameter:
                  - /;/
                  - /['"=]/

- rule:
    id: 920160
    comment: Check to ensure content-length header is numeric
    meta:
        name: Content-length numeric header
        strategy: whitelist
        message: "Content-Length HTTP header is not numeric"
        paranoia-level: 1
        version: OWASP_CRS/3.1.0
        tags:
            - CAPEC:
                - 272
    ensure:
        variables:
            - REQUEST_HEADERS:Content-Length
        checks:
            - operator: rx
              parameter:
                  - /^\d+$/
        mode:
          - required

```


      


