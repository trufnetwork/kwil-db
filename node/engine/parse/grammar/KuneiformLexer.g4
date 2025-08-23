/*
 * A ANTLR4 grammar for Kuneiform.
 * Developed by the Kwil team.
*/

lexer grammar KuneiformLexer;

options { caseInsensitive = true; }

// symbols
LBRACE:     '{';
RBRACE:     '}';
LBRACKET:   '[';
RBRACKET:   ']';
COL:        ':';
SCOL:       ';';
LPAREN:     '(';
RPAREN:     ')';
COMMA:      ',';
AT:         '@';
EXCL:       '!';
PERIOD:     '.';
CONCAT:     '||';
STAR:       '*';
EQUALS:     '=';
EQUATE:     '==';
HASH:       '#';
DOLLAR:     '$';
MOD:        '%';
PLUS:       '+';
MINUS:      '-';
DIV:        '/';
EXP:        '^';
NEQ:        '!='|'<>';
LT:         '<';
LTE:        '<=';
GT:         '>';
GTE:        '>=';
TYPE_CAST:  '::';
UNDERSCORE: '_';
ASSIGN:     ':=';
RANGE:      '..';
DOUBLE_QUOTE: '"';


// top-level blocks
USE:        'use';
UNUSE:      'unuse';
TABLE:      'table';
ACTION:     'action';

// keywords
CREATE:     'create';
ALTER:      'alter';
COLUMN:     'column';
ADD:        'add';
DROP:       'drop';
RENAME:     'rename';
TO:         'to';
CONSTRAINT: 'constraint';
CHECK:      'check';
FOREIGN:    'foreign';
PRIMARY:    'primary';
KEY:        'key';
ON:         'on';
DO:         'do';
UNIQUE:     'unique';
CASCADE:    'cascade';
RESTRICT:   'restrict';
SET:        'set';
DEFAULT:    'default';
NULL:       'null';
DELETE:     'delete';
UPDATE:     'update';
REFERENCES: 'references';
REF:        'ref';
NOT:        'not';
INDEX:      'index';
AND:        'and';
OR:         'or';
LIKE:       'like';
ILIKE:      'ilike';
IN:         'in';
BETWEEN:    'between';
IS:         'is';
EXISTS:     'exists';
ALL:        'all';
ANY:        'any';
JOIN:       'join'; // we only support inner, left, and right joins
LEFT:       'left';
RIGHT:      'right';
INNER:      'inner';
AS:        'as';
ASC:        'asc';
DESC:       'desc';
LIMIT:      'limit';
OFFSET:     'offset';
ORDER:      'order';
BY:         'by';
GROUP:      'group';
HAVING:     'having';
RETURNS:    'returns';
NO:         'no';
WITH:       'with';
CASE:       'case';
WHEN:       'when';
THEN:       'then';
END:        'end';
DISTINCT:   'distinct';
FROM:       'from';
WHERE:      'where';
COLLATE:    'collate';
SELECT:     'select';
INSERT:     'insert';
VALUES:     'values';
FULL:       'full';
UNION:      'union';
INTERSECT:  'intersect';
EXCEPT:     'except';
NULLS:      'nulls';
FIRST:      'first';
LAST:       'last';
RETURNING:  'returning';
INTO:       'into';
CONFLICT:   'conflict';
NOTHING:    'nothing';
FOR:        'for';
IF:         'if';
ELSEIF:     'elseif';
ELSE:       'else';
BREAK:      'break';
CONTINUE:   'continue';
RETURN:     'return';
NEXT:       'next';
OVER:       'over';
PARTITION:  'partition';
WINDOW:     'window';
FILTER:     'filter';
RECURSIVE:  'recursive';
GRANT:      'grant';
GRANTED:    'granted';
REVOKE:     'revoke';
ROLE:       'role';
REPLACE:    'replace';
ARRAY:      'array';
UNNEST:     'unnest';
CURRENT:    'current';
NAMESPACE:  'namespace';
TRANSFER:   'transfer';
OWNERSHIP:  'ownership';

// role permissions
ROLES:      'roles';
CALL:       'call';


// Literals
STRING_: '\'' ( ~['\\] | '\\' . )* '\'';
TRUE: 'true';
FALSE: 'false';

DIGITS_:
    [0-9]+
;

BINARY_:
    '0x' [0-9a-f]+
;

// for backwards compatibility, constraints that support underscores
// are kept here
LEGACY_FOREIGN_KEY: 'foreign_key' | 'fk';
LEGACY_ON_UPDATE: 'on_update';
LEGACY_ON_DELETE: 'on_delete';
LEGACY_SET_DEFAULT: 'set_default';
LEGACY_SET_NULL: 'set_null';
LEGACY_NO_ACTION: 'no_action';

IDENTIFIER:
    [a-z] [a-z_0-9]*
;

VARIABLE:
    DOLLAR IDENTIFIER
;

CONTEXTUAL_VARIABLE:
    AT IDENTIFIER
;

HASH_IDENTIFIER:
    HASH IDENTIFIER
;

WS:            [ \u000B\t\r\n]        -> channel(HIDDEN);
BLOCK_COMMENT: '/*' .*? '*/' -> channel(HIDDEN);
LINE_COMMENT:  '//' ~[\r\n]* -> channel(HIDDEN);
SQL_COMMENT:   '--' ~[\r\n]* -> channel(HIDDEN);