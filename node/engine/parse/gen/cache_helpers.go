package gen

import "github.com/antlr4-go/antlr/v4"

// ParserATN returns the ATN from the parser static data.
func ParserATN() *antlr.ATN {
	return KuneiformParserParserStaticData.atn
}

// SetParserDFA sets a DFA entry in the parser static data.
func SetParserDFA(index int, dfa *antlr.DFA) {
	KuneiformParserParserStaticData.decisionToDFA[index] = dfa
}

// LexerATN returns the ATN from the lexer static data.
func LexerATN() *antlr.ATN {
	return KuneiformLexerLexerStaticData.atn
}

// SetLexerDFA sets a DFA entry in the lexer static data.
func SetLexerDFA(index int, dfa *antlr.DFA) {
	KuneiformLexerLexerStaticData.decisionToDFA[index] = dfa
}
