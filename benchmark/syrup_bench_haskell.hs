{-# LANGUAGE OverloadedStrings #-}
-- Self-contained OCapN Syrup encoder/decoder benchmark.
-- No external library dependencies beyond base, bytestring, binary, criterion.
-- Wire format: OCapN spec (42+ / 42-), matching Python and Node benchmarks.

module Main (main) where

import Criterion.Main
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as LBS
import Data.Binary.Get
import Data.Char (digitToInt, isDigit)
import Data.List (sortBy)
import Data.Ord (comparing)
import Data.Word (Word8)
import Control.DeepSeq (NFData(..), force)

-- ── Types ───────────────────────────────────────────────────────────────────

data SyrupVal
  = SBool   !Bool
  | SInt    !Integer
  | SDouble !Double
  | SBytes  !BS.ByteString
  | SStr    !BS.ByteString
  | SSym    !BS.ByteString
  | SList   ![SyrupVal]
  | SDict   ![(BS.ByteString, SyrupVal)]
  | SRecord !BS.ByteString ![SyrupVal]
  deriving (Show, Eq)

instance NFData SyrupVal where
  rnf (SBool b)      = rnf b
  rnf (SInt n)       = rnf n
  rnf (SDouble d)    = rnf d
  rnf (SBytes b)     = rnf b
  rnf (SStr s)       = rnf s
  rnf (SSym s)       = rnf s
  rnf (SList xs)     = rnf xs
  rnf (SDict kvs)    = rnf kvs
  rnf (SRecord t as) = rnf t `seq` rnf as

-- ── Encoder ─────────────────────────────────────────────────────────────────

encodeVal :: SyrupVal -> BB.Builder
encodeVal (SBool True)   = BB.char8 't'
encodeVal (SBool False)  = BB.char8 'f'
encodeVal (SInt n)
  | n == 0    = BB.string8 "0+"
  | n > 0     = BB.string8 (show n) <> BB.char8 '+'
  | otherwise = BB.string8 (show (negate n)) <> BB.char8 '-'
encodeVal (SDouble d)    = BB.char8 'D' <> BB.doubleBE d
encodeVal (SBytes bs)    =
  BB.string8 (show (BS.length bs)) <> BB.char8 ':' <> BB.byteString bs
encodeVal (SStr bs)      =
  BB.string8 (show (BS.length bs)) <> BB.char8 '"' <> BB.byteString bs
encodeVal (SSym bs)      =
  BB.string8 (show (BS.length bs)) <> BB.char8 '\'' <> BB.byteString bs
encodeVal (SList xs)     =
  BB.char8 '[' <> mconcat (map encodeVal xs) <> BB.char8 ']'
encodeVal (SDict kvs)    =
  BB.char8 '{' <>
  mconcat [ encodeVal (SStr k) <> encodeVal v
          | (k,v) <- sortBy (comparing fst) kvs ] <>
  BB.char8 '}'
encodeVal (SRecord tag args) =
  BB.char8 '<' <> encodeVal (SSym tag) <>
  mconcat (map encodeVal args) <> BB.char8 '>'

encode :: SyrupVal -> LBS.ByteString
encode = BB.toLazyByteString . encodeVal

-- ── Decoder ─────────────────────────────────────────────────────────────────

getVal :: Get SyrupVal
getVal = do
  b <- lookAhead getWord8
  case (toEnum (fromIntegral b) :: Char) of
    't' -> getWord8 >> return (SBool True)
    'f' -> getWord8 >> return (SBool False)
    'D' -> getWord8 >> SDouble <$> getDoublebe
    '[' -> getWord8 >> getListUntil ']' >>= return . SList
    '{' -> getWord8 >> getDictUntil  >>= return . SDict
    '<' -> getWord8 >> getRecord
    _   -> getIntOrLen

getIntOrLen :: Get SyrupVal
getIntOrLen = do
  digits <- getDigits
  tag    <- getWord8
  case (toEnum (fromIntegral tag) :: Char) of
    '+' -> return $ SInt (read digits)
    '-' -> return $ SInt (negate (read digits))
    ':' -> SBytes <$> getByteString (read digits)
    '"' -> SStr   <$> getByteString (read digits)
    '\'' -> SSym  <$> getByteString (read digits)
    c   -> fail $ "unknown tag: " ++ [c]

getDigits :: Get String
getDigits = do
  b <- getWord8
  let c = toEnum (fromIntegral b) :: Char
  if isDigit c
    then (c:) <$> getDigits
    else fail $ "expected digit, got " ++ [c]

-- Special zero: encoded as "0+"
getVal' :: Get SyrupVal
getVal' = do
  b <- lookAhead getWord8
  if b == 0x30  -- '0'
    then do
      _ <- getWord8
      tag <- getWord8
      case tag of
        0x2b -> return (SInt 0)  -- '+'
        _    -> fail "expected + after 0"
    else getVal

getListUntil :: Char -> Get [SyrupVal]
getListUntil end = do
  b <- lookAhead getWord8
  if b == fromIntegral (fromEnum end)
    then getWord8 >> return []
    else do
      v  <- getVal
      vs <- getListUntil end
      return (v:vs)

getDictUntil :: Get [(BS.ByteString, SyrupVal)]
getDictUntil = do
  b <- lookAhead getWord8
  if b == 0x7d  -- '}'
    then getWord8 >> return []
    else do
      k  <- getVal
      v  <- getVal
      rest <- getDictUntil
      case k of
        SStr s -> return ((s, v) : rest)
        _      -> fail "dict key must be string"

getRecord :: Get SyrupVal
getRecord = do
  tag  <- getVal
  args <- getListUntil '>'
  case tag of
    SSym s -> return (SRecord s args)
    _      -> fail "record tag must be symbol"

decodeVal :: LBS.ByteString -> Either String SyrupVal
decodeVal bs = case runGetOrFail getVal bs of
  Left  (_, _, err) -> Left err
  Right (_, _, v)   -> Right v

-- ── Payloads ────────────────────────────────────────────────────────────────

encInt    = encode (SInt 42)
encBool   = encode (SBool True)
encDouble = encode (SDouble 3.14)
encBytes  = encode (SBytes "hello world")
encStr    = encode (SStr "hello world")
encSym    = encode (SSym "op:deliver")
encRecord = encode (SRecord "op:deliver" [SInt 1, SSym "answer", SStr "hello"])
encList100 = encode (SList [ SInt (fromIntegral i) | i <- [0..99 :: Int] ])

-- ── Main ────────────────────────────────────────────────────────────────────

main :: IO ()
main = defaultMain
  [ bgroup "encode"
      [ bench "int (42)"            $ nf encode (SInt 42)
      , bench "bool (True)"         $ nf encode (SBool True)
      , bench "double (3.14)"       $ nf encode (SDouble 3.14)
      , bench "bytes (11 b)"        $ nf encode (SBytes "hello world")
      , bench "string (11 b)"       $ nf encode (SStr "hello world")
      , bench "symbol (op:deliver)" $ nf encode (SSym "op:deliver")
      , bench "record (3 args)"     $ nf encode
            (SRecord "op:deliver" [SInt 1, SSym "answer", SStr "hello"])
      , bench "list (100 ints)"     $ nf encode
            (SList [ SInt (fromIntegral i) | i <- [0..99 :: Int] ])
      ]
  , bgroup "decode"
      [ bench "int (42)"            $ nf decodeVal encInt
      , bench "bool (True)"         $ nf decodeVal encBool
      , bench "double (3.14)"       $ nf decodeVal encDouble
      , bench "bytes (11 b)"        $ nf decodeVal encBytes
      , bench "string (11 b)"       $ nf decodeVal encStr
      , bench "symbol (op:deliver)" $ nf decodeVal encSym
      , bench "record (3 args)"     $ nf decodeVal encRecord
      , bench "list (100 ints)"     $ nf decodeVal encList100
      ]
  ]
