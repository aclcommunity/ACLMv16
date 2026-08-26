"""ACLM lexer — line-oriented, metal-friendly."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum, auto
from typing import List


class T(Enum):
    EOF = auto()
    NEWLINE = auto()
    IDENT = auto()
    NUMBER = auto()
    STRING = auto()
    LABEL = auto()          # ~name as single token content without ~
    OP = auto()             # = + punctuation words handled as IDENT
    LBRACK = auto()
    RBRACK = auto()
    COMMA = auto()
    COLON = auto()
    DOT = auto()
    PLUS = auto()
    MINUS = auto()
    EQ = auto()
    STAR = auto()
    LPAREN = auto()
    RPAREN = auto()
    TILDE = auto()


@dataclass
class Tok:
    kind: T
    value: str
    line: int
    col: int


class Lexer:
    def __init__(self, src: str, filename: str = "<src>"):
        self.src = src
        self.filename = filename
        self.i = 0
        self.line = 1
        self.col = 1
        self.n = len(src)

    def _peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.src[j] if j < self.n else ""

    def _adv(self) -> str:
        ch = self.src[self.i]
        self.i += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def tokenize(self) -> List[Tok]:
        out: List[Tok] = []
        while self.i < self.n:
            ch = self._peek()
            if ch in " \t\r":
                self._adv()
                continue
            if ch == "\n":
                out.append(Tok(T.NEWLINE, "\\n", self.line, self.col))
                self._adv()
                continue
            if ch == "#":
                while self._peek() and self._peek() != "\n":
                    self._adv()
                continue
            line, col = self.line, self.col
            if ch == '"':
                out.append(self._string(line, col))
                continue
            if ch == "[":
                self._adv()
                out.append(Tok(T.LBRACK, "[", line, col))
                continue
            if ch == "]":
                self._adv()
                out.append(Tok(T.RBRACK, "]", line, col))
                continue
            if ch == ",":
                self._adv()
                out.append(Tok(T.COMMA, ",", line, col))
                continue
            if ch == ":":
                self._adv()
                out.append(Tok(T.COLON, ":", line, col))
                continue
            if ch == ".":
                self._adv()
                out.append(Tok(T.DOT, ".", line, col))
                continue
            if ch == "+":
                self._adv()
                out.append(Tok(T.PLUS, "+", line, col))
                continue
            if ch == "=":
                self._adv()
                out.append(Tok(T.EQ, "=", line, col))
                continue
            if ch == "*":
                self._adv()
                out.append(Tok(T.STAR, "*", line, col))
                continue
            if ch == "(":
                self._adv()
                out.append(Tok(T.LPAREN, "(", line, col))
                continue
            if ch == ")":
                self._adv()
                out.append(Tok(T.RPAREN, ")", line, col))
                continue
            if ch == "~":
                self._adv()
                # ~label — letters, digits, underscore allowed after first char
                ch2 = self._peek()
                if ch2.isalpha() or ch2 == "_" or ch2.isdigit():
                    name = self._label_body()
                    out.append(Tok(T.LABEL, name, line, col))
                else:
                    out.append(Tok(T.TILDE, "~", line, col))
                continue
            if ch == "-":
                if self._peek(1).isdigit():
                    self._adv()
                    num = self._number_body()
                    out.append(Tok(T.NUMBER, str(-int(num, 0)), line, col))
                else:
                    self._adv()
                    out.append(Tok(T.MINUS, "-", line, col))
                continue
            if ch.isdigit():
                num = self._number_body()
                out.append(Tok(T.NUMBER, num, line, col))
                continue
            if ch == "@":
                self._adv()
                if self._peek().isalpha():
                    ident = "@" + self._ident_body()
                    out.append(Tok(T.IDENT, ident, line, col))
                else:
                    raise SyntaxError(f"{self.filename}:{line}:{col}: stray @")
                continue
            if ch.isalpha() or ch == "_":
                ident = self._ident_body()
                out.append(Tok(T.IDENT, ident, line, col))
                continue
            if ch == "-":
                self._adv()
                out.append(Tok(T.MINUS, "-", line, col))
                continue
            raise SyntaxError(f"{self.filename}:{line}:{col}: unexpected character {ch!r}")
        out.append(Tok(T.EOF, "", self.line, self.col))
        return out

    def _label_body(self) -> str:
        s = []
        while True:
            ch = self._peek()
            if not ch:
                break
            if ch.isalnum() or ch == "_":
                s.append(self._adv())
            else:
                break
        return "".join(s)

    def _ident_body(self) -> str:
        s = []
        while True:
            ch = self._peek()
            if not ch:
                break
            if ch == ":":
                break
            if ch.isalnum() or ch == "_":
                s.append(self._adv())
            else:
                break
        return "".join(s)

    def _number_body(self) -> str:
        s = []
        if self._peek() == "0" and self._peek(1) in ("x", "X"):
            s.append(self._adv())
            s.append(self._adv())
            while self._peek() and self._peek().isalnum():
                s.append(self._adv())
            return "".join(s)
        while self._peek() and self._peek().isdigit():
            s.append(self._adv())
        return "".join(s) or "0"

    def _string(self, line: int, col: int) -> Tok:
        self._adv()  # "
        s = []
        while self._peek() and self._peek() != '"':
            if self._peek() == "\\" and self._peek(1):
                self._adv()
                esc = self._adv()
                s.append({"n": "\n", "t": "\t", "\\": "\\", '"': '"'}.get(esc, esc))
            else:
                s.append(self._adv())
        if self._peek() != '"':
            raise SyntaxError(f"{self.filename}:{line}:{col}: unterminated string")
        self._adv()
        return Tok(T.STRING, "".join(s), line, col)
