# pointless

```
Written by virchau13
1 (100% liked) 0

What do you mean it's point-free? You can SEE the points!
```

Attachment provides a Haskell code

```haskell
import Data.Char
import Data.Set (Set)
import qualified Data.Set as Set
import Data.List
import Data.Bits
import GHC.Num
import System.IO
import Data.Function
import Control.Monad

if' c t f = if c then t else f

checkFlag = (9808081677743135172288409775188158796289815169603605322273727506636905106808987096987267047244859212186619239940023129609388059687300704940688943841969983867118828709966912736034579721516747709253350210 ==) . flip (flip flip (((map fst . takeWhile snd . fix . const . ap ((:) . flip (,) True . fst . head) (ap (zipWith (flip ((,) . fst) . snd)) tail)) .) . (`ap` flip (fix (ap ((.) . flip if' ([]) . (([]) ==)) . (`ap` (Set.insert . head)) . (((.) . ap (:)) .) . (. tail))) Set.empty) . zipWith . flip ((.) . (,)) . flip ((<) . length)) . ap (flip . ((flip . (ap (flip flip ((flip (liftM2 (++) fst . (. snd) . (:)) .) . splitAt) . flip flip (fix . ((ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail) . (. head) . flip) .) . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip . (flip .) . flip) . ((.) .) . flip flip (fix (ap (flip if' 0 . null) . flip flip ((1 +) . fromIntegral . integerLogBase 3) . flip flip (. fromIntegral) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .) . ap ((.) . ap . (liftM2 (ap . ((.) .) . flip (if' . (0 ==)) . (3 +)) .) . flip flip 2 . (flip .) . flip (.)) (ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.)))) . (flip .) . flip flip (fix ((ap (flip if' ([]) . null) .) . (`ap` splitAt) . (((.) . liftM2 (:) fst) .) . flip flip snd . ((.) .))) . ((flip . ((flip . flip ((.) . ap (.) (map . (. map fromIntegral)))) .) . flip ((.) . flip zipWith [0..] . flip . ((!!) .))) .) . flip . flip id) .)) .) . ap ((.) . flip . (flip .) . (.) . (.) . map . (!!)) (map . (fromIntegral .) . flip rem . toInteger . length)) length) (fix ((1 :) . (2 :) . (3 :) . ap (zipWith (+) . tail . tail) (zipWith (+) =<< tail)))

main = do
    putStr "Input flag: "
    hFlush stdout
    flag <- getLine
    putStrLn $ if checkFlag $ map ord flag then "Correct" else "Wrong"
```

After manual deobfucsation using hand transformation of Lambda Calculus:

```haskell
import Data.Char
import Data.Set (Set)
import qualified Data.Set as Set
import Data.List
import Data.Bits
import GHC.Num
import System.IO
import Data.Function
import Control.Monad

if' c t f = if c then t else f

-- tribonacci numbers
tribonacci = (fix ((1 :) . (2 :) . (3 :) . ap (zipWith (+) . tail . tail) (zipWith (+) =<< tail)))

-- ifGreateThenLength = flip ((<) . length)
ifGreateThenLength x y = x > (length y)

-- reorder = flip ((.) . (,))
reorder x y z = (y, x z)

-- convertPrefixToSet: prefix list to set operation
-- convertPrefixToSet [1,2,3,1]
-- [fromList [1],fromList [1,2],fromList [1,2,3],fromList [1,2,3]]
convertPrefixToSetInner = fix (ap ((.) . flip if' ([]) . (([]) ==)) . (`ap` (Set.insert . head)) . (((.) . ap (:)) .) . (. tail))
convertPrefixToSet :: [Int] -> [Set Int]
convertPrefixToSet x = convertPrefixToSetInner x Set.empty

-- checkPrefixUniqueCountLower: check if prefix uniq numbers lower than input
-- checkPrefixUniqueCountLower 5 [1,2,3,4,5,1,2]
-- [(1,True),(2,True),(3,True),(4,True),(5,False),(1,False),(2,False)]
-- prefix uniq numbers: 1,2,3,4,5,5,5
checkPrefixUniqueCountLower :: Int -> [Int] -> [(Int, Bool)]
checkPrefixUniqueCountLower = (`ap` convertPrefixToSet) . zipWith . reorder . ifGreateThenLength

-- dropFirstInt: drop first number, keep order of Bool
-- dropFirstInt [(100,True),(2,False),(3,True)]
-- [(2,True),(3,False)]
dropFirstInt = ap (zipWith (flip ((,) . fst) . snd)) tail

-- getFirstWithTrueAndConcat = (:) . flip (,) True . fst . head
-- getFirstWithTrueAndConcat [(1, 2), (3, 4)] [(5, False)]
-- [(1,True),(5,False)]
getFirstWithTrueAndConcat :: [(b1, b2)] -> [(b1, Bool)] -> [(b1, Bool)]
getFirstWithTrueAndConcat x y = ((fst (head x)), True) : y

-- shiftBoolRightPrependTrue x = ap getFirstWithTrueAndConcat dropFirstInt x
-- shift Bool right, prepend True
-- shiftBoolRightPrependTrue [(2,False),(3,True),(4,True)]
-- [(2,True),(3,False),(4,True)]
shiftBoolRightPrependTrue :: [(b1, Bool)] -> [(b1, Bool)]
shiftBoolRightPrependTrue x = getFirstWithTrueAndConcat x (dropFirstInt x)

-- get all ints in prefix until the first False
-- takeUntilFirstFalse [(2,True),(3,False),(4,True)]
-- [2,3]
takeUntilFirstFalse = map fst . takeWhile snd . fix . const . shiftBoolRightPrependTrue

transformArrayToInt :: [Integer] -> Integer
-- transformArrayToInt [0]: 3-based 10
-- transformArrayToInt [1]: 3-based 11
-- transformArrayToInt [2]: 3-based 21
-- transformArrayToInt [3]: 3-based 102
-- transformArrayToInt [4]: 3-based 112
-- transformArrayToInt [5]: 3-based 122
-- transformArrayToInt [6]: 3-based 202
-- transformArrayToInt [7]: 3-based 212
-- transformArrayToInt [8]: 3-based 222
-- transformArrayToInt [9]: 3-based 10010
-- transformArrayToInt [10]: 3-based 10110
-- transformArrayToInt [11]: 3-based 10210
-- transformArrayToInt [12]: 3-based 11010
-- transformArrayToInt [13]: 3-based 11110
-- transformArrayToInt [14]: 3-based 11210
-- transformArrayToInt [15]: 3-based 12010
-- transformArrayToInt [16]: 3-based 12110
-- transformArrayToInt [17]: 3-based 12210
-- transformArrayToInt [18]: 3-based 20010
-- transformArrayToInt [19]: 3-based 20110
-- transformArrayToInt [26]: 3-based 22210
-- transformArrayToInt [27]: 3-based 100011
-- transformArrayToInt [28]: 3-based 100111
-- transformArrayToInt [81]: 3-based 1000012
-- transformArrayToInt [82]: 3-based 1000112
-- transformArrayToInt [243]: 3-based 10000020
-- transformArrayToInt [244]: 3-based 10000120
-- transformArrayToInt [729]: 3-based 100000021
-- transformArrayToInt [730]: 3-based 100000121
-- transformArrayToInt [19691]: 3-based 1000000022
-- transformArrayToInt [177156]: 3-based 100000000100
-- transformArrayToInt [177157]: 3-based 100000001100
-- transformArrayToInt [0,0]: 3+3^3
-- transformArrayToInt [0,0,0]: 3+3^3+3^5
-- transformArrayToInt [0,0,0,0]: 3-based 010101010
-- transformArrayToInt [1,0,0,0]: 3-based 010101011
-- transformArrayToInt [0,1,0,0]: 3-based 010101110
-- transformArrayToInt [0,0,1,0]: 3-based 010111010
-- transformArrayToInt [0,0,0,1]: 3-based 011101010
-- transformArrayToInt [2,0,0,0]: 3-based 010101021
-- transformArrayToInt [0,2,0,0]: 3-based 010102110
-- transformArrayToInt [0,0,2,0]: 3-based 010211010
-- transformArrayToInt [0,0,0,2]: 3-based 021101010
-- transformArrayToInt [3,0,0,0]: 3-based 101010102
-- transformArrayToInt [0,3,0,0]: 3-based 101010210
-- transformArrayToInt [0,0,3,0]: 3-based 101010210
-- transformArrayToInt [0,0,3,0]: 3-based 101021010
-- transformArrayToInt [0,0,0,3]: 3-based 102101010
-- transformArrayToInt [27,0,0,0]: 3-based 101010100011
-- 3-based representation concatenated
transformArrayToInt = fix transformArrayToIntInner
transformArrayToIntInner = ap (flip if' 0 . null) . flip flip ((1 +) . fromIntegral . integerLogBase 3) . flip flip (. fromIntegral) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .) . ap ((.) . ap . (liftM2 (ap . ((.) .) . flip (if' . (0 ==)) . (3 +)) .) . flip flip 2 . (flip .) . flip (.)) (ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.))

-- insertTo: insert element into the list
-- insertTo 2 [1,2,3,4] 5
-- insertTo 2 [1,2,3,4] 5
insertTo :: Int -> [a] -> a -> [a]
insertTo = ((flip (liftM2 (++) fst . (. snd) . (:)) .) . splitAt)

-- splitChunks 1 [1,2,3,4,5]
-- [[1],[2],[3],[4],[5]]
-- splitChunks 2 [1,2,3,4,5]
-- [[1,2],[3,4],[5]]
splitChunks :: Int -> [a] -> [[a]]
splitChunks = (fix ((ap (flip if' ([]) . null) .) . (`ap` splitAt) . (((.) . liftM2 (:) fst) .) . flip flip snd . ((.) .)))

-- mapModLength x y: for each element in y, % length of x
-- mapModLength [0,0] [1,2,3]
-- [1,0,1]
mapModLength :: [a] -> [Integer] -> [Int]
mapModLength = map . (fromIntegral .) . flip rem . toInteger . length

-- get prefix until uniq elements count to x
-- getPrefixUntilUniqCountTo 5 [1,2,3,4,4,5,4,3,2,2]
-- [1,2,3,4,4,5]
getPrefixUntilUniqCountTo :: Int -> [Int] -> [Int]
getPrefixUntilUniqCountTo x y = takeUntilFirstFalse (checkPrefixUniqueCountLower x y)

-- (fix recurseFunction): generate permutation
recurseFunction recurse c = if' (null c) [([])]
    (if' (1 == (length c)) (return (return ((head c))))
        ((recurse (tail c) >>= ((\x -> map (\e -> (insertTo e x) (head c)) (enumFromTo 0 (length x)))))))

getElementsByTribonacci :: [a] -> [a]
getElementsByTribonacci x = map (\idx -> x !! idx) (getPrefixUntilUniqCountTo (length x) (mapModLength x tribonacci))

step1 x = splitChunks (length x) (getElementsByTribonacci x)
step2 x = zipWith (\y z -> (!!) (((fix recurseFunction) z)) y) [0..] (step1 x)
step3 x = map (\y -> transformArrayToInt (map fromIntegral y)) (step2 x)

computeFlag x = transformArrayToInt (step3 x)

checkFlag = (9808081677743135172288409775188158796289815169603605322273727506636905106808987096987267047244859212186619239940023129609388059687300704940688943841969983867118828709966912736034579721516747709253350210 ==) . computeFlag

main = do
    print $ computeFlag $ map ord "\x00"
    print $ checkFlag $ map ord "\x00"
```

After that, we can find the intermediates values from the target value and eventually find the flag:

```python
from itertools import batched
import numpy


def tribonacci():
    a, b, c = 1, 2, 3  # T(0), T(1), T(2)

    while True:
        yield a
        next_trib = a + b + c
        a = b
        b = c
        c = next_trib


# map (\x -> transformArrayToInt [x]) (enumFromTo 0 128)
mapping = [
    3,
    4,
    7,
    11,
    14,
    17,
    20,
    23,
    26,
    84,
    93,
    102,
    111,
    120,
    129,
    138,
    147,
    156,
    165,
    174,
    183,
    192,
    201,
    210,
    219,
    228,
    237,
    247,
    256,
    265,
    274,
    283,
    292,
    301,
    310,
    319,
    328,
    337,
    346,
    355,
    364,
    373,
    382,
    391,
    400,
    409,
    418,
    427,
    436,
    445,
    454,
    463,
    472,
    481,
    490,
    499,
    508,
    517,
    526,
    535,
    544,
    553,
    562,
    571,
    580,
    589,
    598,
    607,
    616,
    625,
    634,
    643,
    652,
    661,
    670,
    679,
    688,
    697,
    706,
    715,
    724,
    734,
    743,
    752,
    761,
    770,
    779,
    788,
    797,
    806,
    815,
    824,
    833,
    842,
    851,
    860,
    869,
    878,
    887,
    896,
    905,
    914,
    923,
    932,
    941,
    950,
    959,
    968,
    977,
    986,
    995,
    1004,
    1013,
    1022,
    1031,
    1040,
    1049,
    1058,
    1067,
    1076,
    1085,
    1094,
    1103,
    1112,
    1121,
    1130,
    1139,
    1148,
    1157,
]


def compute(e):
    # compute integer log3
    order = 0
    num = 1
    while num <= e:
        num *= 3
        order += 1

    # low part
    low = order
    # high part
    diff = e - (num // 3)
    high = diff + 3 ** (order - 1)

    if e < len(mapping):
        assert numpy.base_repr(mapping[e], 3) == numpy.base_repr(
            high, 3
        ) + numpy.base_repr(low, 3)

    part = numpy.base_repr(high, 3) + numpy.base_repr(low, 3)
    return part


def transform(arr):
    result = str()
    # handle each element
    for e in arr:
        # compute integer log3
        order = 0
        num = 1
        while num <= e:
            num *= 3
            order += 1

        # low part
        low = order
        # high part
        diff = e - (num // 3)
        high = diff + 3 ** (order - 1)

        if e < len(mapping):
            assert numpy.base_repr(mapping[e], 3) == numpy.base_repr(
                high, 3
            ) + numpy.base_repr(low, 3)

        part = numpy.base_repr(high, 3) + numpy.base_repr(low, 3)
        # print(e, "->", part)
        result = part + result
    return int(result, 3)


def permutations(array):
    if len(array) == 0:
        yield []
    elif len(array) == 1:
        yield [array[0]]
    else:
        gen = permutations(array[1:])
        while True:
            entry = next(gen)
            if entry is None:
                break
            for i in range(len(array)):
                temp = entry[:i] + [array[0]] + entry[i:]
                yield temp


def compute_flag(s):
    chars = [ord(x) for x in s]
    length = len(chars)
    # getElementsByTribonacci
    uniq = set()
    prefix = []
    gen = tribonacci()
    while len(uniq) < length:
        value = next(gen) % length
        prefix.append(chars[value])
        uniq.add(value)

    # step1, split chunks
    chunks = list(batched(prefix, length))

    # step2, permutation and zip
    permutes = []
    for i, chunk in enumerate(chunks):
        gen = permutations(chunk)
        cur = next(gen)
        for j in range(i):
            cur = next(gen)
        permutes += [cur]

    # step 3, to int
    ints = [transform(x) for x in permutes]
    return transform(ints)


# sanity check
test = compute_flag("abcd")
print(test)
assert test == 99068139562419619151725

# preprocess printable characters
preprocessed = dict()
for i in range(0x20, 0x7F):
    preprocessed[numpy.base_repr(transform([i]), 3)] = i

target = 9808081677743135172288409775188158796289815169603605322273727506636905106808987096987267047244859212186619239940023129609388059687300704940688943841969983867118828709966912736034579721516747709253350210
encoded = numpy.base_repr(target, 3)

i = 0


def find_part(encoded):
    for length in range(len(encoded) - 1, 0, -1):
        low = numpy.base_repr(length, 3)
        if length + len(low) > len(encoded):
            continue
        if encoded[length : length + len(low)] == low:
            high = int(encoded[:length], 3)
            order = length
            diff = high - 3 ** (order - 1)
            e = diff + (3**order // 3)

            part = compute(e)

            assert part == encoded[: length + len(low)]

            e_enc = numpy.base_repr(e, 3)
            data = bytearray()
            i = 0
            good = True
            while i < len(e_enc):
                if e_enc[i : i + 7] in preprocessed:
                    data.append(preprocessed[e_enc[i : i + 7]])
                    i += 7
                elif e_enc[i : i + 6] in preprocessed:
                    data.append(preprocessed[e_enc[i : i + 6]])
                    i += 6
                else:
                    good = False
                    break

            if not good:
                continue

            print()
            print("e", e_enc)
            print(data)
            rest = encoded[length + len(low) :]
            print("rest:", rest)
            find_part(rest)


find_part(encoded)

# validate
part1 = bytearray(b"w}t}yf17x_yl1nu7u_1f_31ntl__s3")
part2 = bytearray(b"1s1c3crnx31cr3_74n4f__{7tf13{cta")

permutes = list(reversed([[x for x in reversed(part1)], [x for x in reversed(part2)]]))
ints = [transform(x) for x in permutes]
print([numpy.base_repr(i, 3) for i in ints])
print(transform(ints))
assert transform(ints) == target

chunks = [list(permutes[0]), list(permutes[1])]
# permute manually
chunks[1][0], chunks[1][1] = chunks[1][1], chunks[1][0]

# validate
temp = []
for i, chunk in enumerate(chunks):
    gen = permutations(chunk)
    cur = next(gen)
    for j in range(i):
        cur = next(gen)
    temp += [cur]

print(temp, permutes)
assert temp == permutes

prefix = chunks[0] + chunks[1]
length = len(chunks[0])

# find flag
flag = [0] * 128
uniq = set()
gen = tribonacci()
i = 0
while len(uniq) < length:
    value = next(gen) % length
    flag[value] = prefix[i]
    i += 1
    if i >= len(prefix):
        break
    uniq.add(value)
print(bytes(flag))
```

The flag is `watctf{_4n_3x3rc1s3_1n_fu71l17y}`.

The full process of manual deobfuscation:

```haskell
import Data.Char
import Data.Set (Set)
import qualified Data.Set as Set
import Data.List
import Data.Bits
import GHC.Num
import System.IO
import Data.Function
import Control.Monad

if' c t f = if c then t else f

checkFlag = (9808081677743135172288409775188158796289815169603605322273727506636905106808987096987267047244859212186619239940023129609388059687300704940688943841969983867118828709966912736034579721516747709253350210 ==) . flip (flip flip (((map fst . takeWhile snd . fix . const . ap ((:) . flip (,) True . fst . head) (ap (zipWith (flip ((,) . fst) . snd)) tail)) .) . (`ap` flip (fix (ap ((.) . flip if' ([]) . (([]) ==)) . (`ap` (Set.insert . head)) . (((.) . ap (:)) .) . (. tail))) Set.empty) . zipWith . flip ((.) . (,)) . flip ((<) . length)) . ap (flip . ((flip . (ap (flip flip ((flip (liftM2 (++) fst . (. snd) . (:)) .) . splitAt) . flip flip (fix . ((ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail) . (. head) . flip) .) . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip . (flip .) . flip) . ((.) .) . flip flip (fix (ap (flip if' 0 . null) . flip flip ((1 +) . fromIntegral . integerLogBase 3) . flip flip (. fromIntegral) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .) . ap ((.) . ap . (liftM2 (ap . ((.) .) . flip (if' . (0 ==)) . (3 +)) .) . flip flip 2 . (flip .) . flip (.)) (ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.)))) . (flip .) . flip flip (fix ((ap (flip if' ([]) . null) .) . (`ap` splitAt) . (((.) . liftM2 (:) fst) .) . flip flip snd . ((.) .))) . ((flip . ((flip . flip ((.) . ap (.) (map . (. map fromIntegral)))) .) . flip ((.) . flip zipWith [0..] . flip . ((!!) .))) .) . flip . flip id) .)) .) . ap ((.) . flip . (flip .) . (.) . (.) . map . (!!)) (map . (fromIntegral .) . flip rem . toInteger . length)) length) (fix ((1 :) . (2 :) . (3 :) . ap (zipWith (+) . tail . tail) (zipWith (+) =<< tail)))

-- tribonacci numbers
tribonacci = (fix ((1 :) . (2 :) . (3 :) . ap (zipWith (+) . tail . tail) (zipWith (+) =<< tail)))

-- ifGreateThenLength = flip ((<) . length)
ifGreateThenLength x y = x > (length y)

-- reorder = flip ((.) . (,))
reorder x y z = (y, x z)

-- convertPrefixToSet: prefix list to set operation
-- convertPrefixToSet [1,2,3,1]
-- [fromList [1],fromList [1,2],fromList [1,2,3],fromList [1,2,3]]
convertPrefixToSetInner = fix (ap ((.) . flip if' ([]) . (([]) ==)) . (`ap` (Set.insert . head)) . (((.) . ap (:)) .) . (. tail))
convertPrefixToSet :: [Int] -> [Set Int]
convertPrefixToSet x = convertPrefixToSetInner x Set.empty

-- checkPrefixUniqueCountLower: check if prefix uniq numbers lower than input
-- checkPrefixUniqueCountLower 5 [1,2,3,4,5,1,2]
-- [(1,True),(2,True),(3,True),(4,True),(5,False),(1,False),(2,False)]
-- prefix uniq numbers: 1,2,3,4,5,5,5
checkPrefixUniqueCountLower :: Int -> [Int] -> [(Int, Bool)]
checkPrefixUniqueCountLower = (`ap` convertPrefixToSet) . zipWith . reorder . ifGreateThenLength

-- dropFirstInt: drop first number, keep order of Bool
-- dropFirstInt [(100,True),(2,False),(3,True)]
-- [(2,True),(3,False)]
dropFirstInt = ap (zipWith (flip ((,) . fst) . snd)) tail

-- getFirstWithTrueAndConcat = (:) . flip (,) True . fst . head
-- getFirstWithTrueAndConcat [(1, 2), (3, 4)] [(5, False)]
-- [(1,True),(5,False)]
getFirstWithTrueAndConcat :: [(b1, b2)] -> [(b1, Bool)] -> [(b1, Bool)]
getFirstWithTrueAndConcat x y = ((fst (head x)), True) : y

-- shiftBoolRightPrependTrue x = ap getFirstWithTrueAndConcat dropFirstInt x
-- shift Bool right, prepend True
-- shiftBoolRightPrependTrue [(2,False),(3,True),(4,True)]
-- [(2,True),(3,False),(4,True)]
shiftBoolRightPrependTrue :: [(b1, Bool)] -> [(b1, Bool)]
shiftBoolRightPrependTrue x = getFirstWithTrueAndConcat x (dropFirstInt x)

-- get all ints in prefix until the first False
-- takeUntilFirstFalse [(2,True),(3,False),(4,True)]
-- [2,3]
takeUntilFirstFalse = map fst . takeWhile snd . fix . const . shiftBoolRightPrependTrue

-- get prefix until uniq elements count to x
-- getPrefixUntilUniqCountTo 5 [1,2,3,4,4,5,4,3,2,2]
-- [1,2,3,4,4,5]
getPrefixUntilUniqCountTo :: Int -> [Int] -> [Int]
getPrefixUntilUniqCountTo x y = takeUntilFirstFalse (checkPrefixUniqueCountLower x y)

part1 = flip flip getPrefixUntilUniqCountTo

-- temp8 :: Int -> [Int] -> Integer
-- temp8 = temp15 . temp20
temp8 a b = temp15 (temp20 a) b

-- temp15
--   :: (a1 -> ([a2] -> [[a2]]) -> ([Integer] -> Integer) -> c)
--      -> a1 -> c
-- temp15 = flip flip insertTo . flip flip temp11 . ((.) .) . flip flip transformArrayToInt . (flip .)
-- temp15 = (\y -> flip y insertTo) . (\y -> flip y temp11) . ((.) .) . (\y -> flip y transformArrayToInt) . (flip .)
-- temp15 = (\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11) . ((.) .) . (\y -> \x -> y x transformArrayToInt) . (\x -> \y -> flip (x y))
-- temp15 a b = ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11) . ((.) .) . (\y -> \x -> y x transformArrayToInt)) (\y -> flip (a y)) b
-- temp15 a b = (\z -> ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11) . ((.) .)) ((\y -> \x -> y x transformArrayToInt) z)) (\y -> flip (a y)) b
-- temp15 a b = ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11) . ((.) .)) ((\y -> \x -> y x transformArrayToInt) (\y -> flip (a y))) b
-- temp15 a b = ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11) . ((.) .)) (\x -> flip (a x) transformArrayToInt) b
-- temp15 a b = ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11)) (((.) .) (\x -> flip (a x) transformArrayToInt)) b
-- temp15 a b = ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11)) ((\x -> (.) . x) (\x -> flip (a x) transformArrayToInt)) b
-- temp15 a b = ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11)) (((.) . (\x -> flip (a x) transformArrayToInt)) ) b
-- temp15 a b = ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11)) (((\x y -> x . y) . (\x -> flip (a x) transformArrayToInt)) ) b
-- temp15 a b = ((\y -> \x -> y x insertTo) . (\y -> \x -> y x temp11)) (\z -> (\y -> (flip (a z) transformArrayToInt) . y)) b
-- temp15 a b = (\c -> (\y -> \x -> y x insertTo) ((\y -> \x -> y x temp11) c)) (\z -> (\y -> (flip (a z) transformArrayToInt) . y)) b
-- temp15 a b = (\y -> \x -> y x insertTo) ((\y -> \x -> y x temp11) (\z -> (\y -> (flip (a z) transformArrayToInt) . y))) b
-- temp15 a b = (\y -> \x -> y x insertTo) ((\x -> (\z -> (\y -> (flip (a z) transformArrayToInt) . y)) x temp11) ) b
-- temp15 a b = (\y -> \x -> y x insertTo) ((\x -> (\y -> (flip (a x) transformArrayToInt) . y) temp11) ) b
-- temp15 a b = (\y -> \x -> y x insertTo) ((\x -> (flip (a x) transformArrayToInt) . temp11)) b
-- temp15 a b = (\x -> ((\x -> (flip (a x) transformArrayToInt) . temp11)) x insertTo) b
-- temp15 a b = (\x -> (flip (a x) transformArrayToInt) . temp11) b insertTo
-- temp15 a b = ((flip (a b) transformArrayToInt) . temp11) insertTo
-- temp15 a b = ((\y -> (a b) y transformArrayToInt) . temp11) insertTo
-- temp15 a b = (\x -> (\y -> (a b) y transformArrayToInt) (temp11 x)) insertTo
-- temp15 a b = (\y -> (a b) y transformArrayToInt) (temp11 insertTo)
temp15 a b = (a b) (temp11 insertTo) transformArrayToInt

-- temp19
--   :: a1
--      -> a2
--      -> (a1 -> a2 -> [b])
--      -> (b -> [[Int]])
--      -> ([Integer] -> Integer)
--      -> Integer
-- temp19 = temp14 . flip . flip id
temp19 a b c d e = temp14 c a b d e

-- temp20
--   :: Int
--      -> [a] -> ([a] -> [[Int]]) -> ([Integer] -> Integer) -> Integer
-- temp20 = flip flip splitChunks . temp19
-- temp20 = (flip flip splitChunks) . temp19
-- temp20 = (\y -> flip y splitChunks) . temp19
-- temp20 a = (\y -> flip y splitChunks) (temp19 a)
-- temp20 a = flip (temp19 a) splitChunks
-- temp20 a = (\y -> (temp19 a) y splitChunks)
-- temp20 a b c d = (temp19 a) b splitChunks c d
temp20 a b c d = temp19 a b splitChunks c d

-- insertTo: insert element into the list
-- insertTo 2 [1,2,3,4] 5
-- insertTo 2 [1,2,3,4] 5
insertTo :: Int -> [a] -> a -> [a]
insertTo = ((flip (liftM2 (++) fst . (. snd) . (:)) .) . splitAt)

-- temp11 :: (Int -> [a] -> a -> [a]) -> [a] -> [[a]]
-- temp11 a = (fix . temp17 . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip . (flip .)) (flip a)
-- temp11 a = (fix . temp17 . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip) (flip . (flip a))
-- temp11 a = (fix . temp17 . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip) (flip . (\x y -> a y x))
-- temp11 a = (fix . temp17 . (. (((.) . (>>=)) .)) . flip flip . (((`ap` (enumFromTo 0 . length)) . (map .)) .) . flip) (\z -> flip ((\x y -> a y x) z))
-- temp11 a = (fix . temp17 . (. (((.) . (>>=)) .)) . flip flip . (\x -> ((`ap` (enumFromTo 0 . length)) . (map .)) . x)) (flip (\z -> flip ((\x y -> a y x) z)))
-- temp11 a = (fix . temp17 . (. (((.) . (>>=)) .)) . flip flip) ((\x -> ((`ap` (enumFromTo 0 . length)) . (map .)) . x) (flip (\z -> flip ((\x y -> a y x) z))))
-- temp11 a = (fix . temp17 . (. (((.) . (>>=)) .)) . flip flip) (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z))))
-- temp11 a = (fix . temp17 . (. (((.) . (>>=)) .))) (flip flip (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z)))))
-- temp11 a = (fix . temp17) ((. (((.) . (>>=)) .)) (flip flip (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z))))))
temp11 a = fix (temp17 ((\x -> x . (((.) . (>>=)) .)) (flip flip (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z)))))))

-- temp11 a b = (fix (temp24 a)) b

-- temp24
--   :: Foldable t =>
--      (Int -> t a -> a2 -> [a2]) -> ([a2] -> [t a]) -> [a2] -> [[a2]]
-- temp24 a b = temp17 (temp25 a) b
-- temp24 a b c = if' (null c) [([])]
--     (if' (1 == (length c)) (return (return ((head c))))
--         (((temp25 a) b) (tail c) (head c)))
-- temp24 a b c = if' (null c) [([])]
--     (if' (1 == (length c)) (return (return ((head c))))
--         (temp25 a b (tail c) (head c)))
-- temp24 a b c = if' (null c) [([])]
--     (if' (1 == (length c)) (return (return ((head c))))
--         ((b (tail c) >>= ((\x -> map (\e -> (a e x) (head c)) (enumFromTo 0 (length x)))))))
-- temp25 a b c d = (b c) >>= ((\x -> map (\e -> (a e x) d) (enumFromTo 0 (length x))))

-- temp25
--   :: Foldable t =>
--      (Int -> t a1 -> a2 -> b) -> (a3 -> [t a1]) -> a3 -> a2 -> [b]
-- temp25 a b = (flip flip (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z))))) ((((.) . (>>=)) .) b)
-- temp25 a b = (flip flip (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z))))) (\w d e -> (b w) >>= (d e))
-- temp25 a b = (\f -> flip f (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z))))) (\w d e -> (b w) >>= (d e))
-- temp25 a b c = flip (\w d e -> (b w) >>= (d e)) (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z)))) c
-- temp25 a b c = (\w d e -> (b w) >>= (d e)) c (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z))))
-- temp25 a b c = (\d e -> (b c) >>= (d e)) (((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z))))
-- temp25 a b c d = (b c) >>= ((((`ap` (enumFromTo 0 . length)) . (map .)) . (flip (\z -> flip ((\x y -> a y x) z)))) d)
-- temp25 a b c d = (b c) >>= (((`ap` (enumFromTo 0 . length)) . (map .)) ((flip (\z -> flip ((\x y -> a y x) z))) d))
-- temp25 a b c d = (b c) >>= ((\e -> (`ap` (enumFromTo 0 . length)) ((map .) e)) ((flip (\z -> flip ((\x y -> a y x) z))) d))
-- temp25 a b c d = (b c) >>= ((\e -> (`ap` (enumFromTo 0 . length)) (map . e)) ((flip (\z -> flip ((\x y -> a y x) z))) d))
-- temp25 a b c d = (b c) >>= ((\x -> x `ap` (enumFromTo 0 . length)) (map . ((flip (\z -> flip ((\x y -> a y x) z))) d)))
-- temp25 a b c d = (b c) >>= (((map . ((flip (\z -> flip ((\x y -> a y x) z))) d)) `ap` (enumFromTo 0 . length)))
-- temp25 a b c d = (b c) >>= ((\x -> (map . ((flip (\z -> flip ((\x y -> a y x) z))) d)) x ((enumFromTo 0 . length) x)))
-- temp25 a b c d = (b c) >>= ((\x -> (map . ((flip (\z -> flip ((\x y -> a y x) z))) d)) x (enumFromTo 0 (length x))))
-- temp25 a b c d = (b c) >>= ((\x -> map (((flip (\z -> flip ((\x y -> a y x) z))) d) x) (enumFromTo 0 (length x))))
-- temp25 a b c d = (b c) >>= ((\x -> map (((\e f -> (\z -> flip ((\x y -> a y x) z)) f e) d) x) (enumFromTo 0 (length x))))
-- temp25 a b c d = (b c) >>= ((\x -> map (flip ((\x y -> a y x) x) d) (enumFromTo 0 (length x))))
-- temp25 a b c d = (b c) >>= ((\x -> map (\e -> ((\x y -> a y x) x) e d) (enumFromTo 0 (length x))))
-- temp25 a b c d = (b c) >>= ((\x -> map (\e -> (a e x) d) (enumFromTo 0 (length x))))

-- temp17 :: (a1 -> [a2] -> a2 -> [[a2]]) -> a1 -> [a2] -> [[a2]]
-- temp17 a b = (ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail) . (. head) . flip) (a b)
-- temp17 a b = (\x -> (ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail) . (. head)) (flip x)) (a b)
-- temp17 a b = (ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail) . (. head)) (flip (a b))
-- temp17 a b = (ap (flip if' [([])] . null) . ap (ap (if' . (1 ==) . length) (return . return . head)) . (`ap` tail)) ((flip (a b)) . head)
-- temp17 a b = (ap (flip if' [([])] . null)) (\y -> (ap (if' . (1 ==) . length) (return . return . head)) y ((\x -> ((flip (a b)) . head) x (tail x)) y))
-- temp17 a b = ap (flip if' [([])] . null) (\y -> (ap (if' . (1 ==) . length) (return . return . head)) y (((flip (a b)) . head) y (tail y)))
-- temp17 a b c = (flip if' [([])] . null) c (((ap (if' . (1 ==) . length) (return . return . head)) c (((flip (a b)) . head) c (tail c))))
-- temp17 a b c = ((flip if' [([])]) . null) c (((ap (if' . (1 ==) . length) (return . return . head)) c (((flip (a b)) . head) c (tail c))))
-- temp17 a b c = ((\x -> if' x [([])]) . null) c (((ap (if' . (1 ==) . length) (return . return . head)) c (((flip (a b)) . head) c (tail c))))
-- temp17 a b c = if' (null c) [([])]
--     (((ap (if' . (1 ==) . length) (return . return . head)) c (((flip (a b)) . head) c (tail c))))
-- temp17 a b c = if' (null c) [([])]
--     ((((if' . (1 ==) . length) c ((return . return . head) c)) (((flip (a b)) . head) c (tail c))))
temp17 a b c = if' (null c) [([])]
    (if' (1 == (length c)) (return (return ((head c))))
        ((a b) (tail c) (head c)))

transformArrayToInt :: [Integer] -> Integer
-- transformArrayToInt [0]: 3-based 10
-- transformArrayToInt [1]: 3-based 11
-- transformArrayToInt [2]: 3-based 21
-- transformArrayToInt [3]: 3-based 102
-- transformArrayToInt [4]: 3-based 112
-- transformArrayToInt [5]: 3-based 122
-- transformArrayToInt [6]: 3-based 202
-- transformArrayToInt [7]: 3-based 212
-- transformArrayToInt [8]: 3-based 222
-- transformArrayToInt [9]: 3-based 10010
-- transformArrayToInt [10]: 3-based 10110
-- transformArrayToInt [11]: 3-based 10210
-- transformArrayToInt [12]: 3-based 11010
-- transformArrayToInt [13]: 3-based 11110
-- transformArrayToInt [14]: 3-based 11210
-- transformArrayToInt [15]: 3-based 12010
-- transformArrayToInt [16]: 3-based 12110
-- transformArrayToInt [17]: 3-based 12210
-- transformArrayToInt [18]: 3-based 20010
-- transformArrayToInt [19]: 3-based 20110
-- transformArrayToInt [26]: 3-based 22210
-- transformArrayToInt [27]: 3-based 100011
-- transformArrayToInt [28]: 3-based 100111
-- transformArrayToInt [81]: 3-based 1000012
-- transformArrayToInt [82]: 3-based 1000112
-- transformArrayToInt [243]: 3-based 10000020
-- transformArrayToInt [244]: 3-based 10000120
-- transformArrayToInt [729]: 3-based 100000021
-- transformArrayToInt [730]: 3-based 100000121
-- transformArrayToInt [19691]: 3-based 1000000022
-- transformArrayToInt [177156]: 3-based 100000000100
-- transformArrayToInt [177157]: 3-based 100000001100
-- transformArrayToInt [0,0]: 3+3^3
-- transformArrayToInt [0,0,0]: 3+3^3+3^5
-- transformArrayToInt [0,0,0,0]: 3-based 010101010
-- transformArrayToInt [1,0,0,0]: 3-based 010101011
-- transformArrayToInt [0,1,0,0]: 3-based 010101110
-- transformArrayToInt [0,0,1,0]: 3-based 010111010
-- transformArrayToInt [0,0,0,1]: 3-based 011101010
-- transformArrayToInt [2,0,0,0]: 3-based 010101021
-- transformArrayToInt [0,2,0,0]: 3-based 010102110
-- transformArrayToInt [0,0,2,0]: 3-based 010211010
-- transformArrayToInt [0,0,0,2]: 3-based 021101010
-- transformArrayToInt [3,0,0,0]: 3-based 101010102
-- transformArrayToInt [0,3,0,0]: 3-based 101010210
-- transformArrayToInt [0,0,3,0]: 3-based 101010210
-- transformArrayToInt [0,0,3,0]: 3-based 101021010
-- transformArrayToInt [0,0,0,3]: 3-based 102101010
-- transformArrayToInt [27,0,0,0]: 3-based 101010100011
-- 3-based representation concatenated
transformArrayToInt = fix transformArrayToIntInner
-- transformArrayToIntInner = ap (flip if' 0 . null) . flip flip ((1 +) . fromIntegral . integerLogBase 3) . flip flip (. fromIntegral) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .) . ap ((.) . ap . (liftM2 (ap . ((.) .) . flip (if' . (0 ==)) . (3 +)) .) . flip flip 2 . (flip .) . flip (.)) (ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.))
transformArrayToIntInner
  :: ([Integer] -> Integer) -> [Integer] -> Integer
-- transformArrayToIntInner recurse = (ap (flip if' 0 . null) . flip flip ((1 +) . fromIntegral . integerLogBase 3) . flip flip (. fromIntegral) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .))
--     ((((.) . ap . (liftM2 (ap . ((.) .) . flip (if' . (0 ==)) . (3 +)) .) . flip flip 2 . (flip .)) (\y -> y . recurse))  ((ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.)) recurse))
transformArrayToIntInner recurse = ((\b x -> (\a -> if' (null a) 0) x (b x)) . (\z w -> z w (\y -> (1 + (fromIntegral (integerLogBase 3 y))))) . flip flip (\x y -> x (fromIntegral y)) . (ap .) . flip flip ((. (3 ^)) . (*)) . ((flip . (flip .)) .) . (`ap` tail) . ((flip . ((flip . (flip .)) .)) .) . (. head) . flip . ((flip . ((flip . (flip .)) .)) .) . flip . ((flip . ((flip . (ap .)) .)) .))
    (((((((.) . ap) (\d -> liftM2 (\e -> ((ap ((\g h i -> (if' (0 == g) (e + 3)) (h i)))))) ((\b -> (d (recurse b)) 2)))) ) ))  ((ap (ap . (((.) . flip . ((ap . ((+) .) . liftM2 (+) toInteger) .)) .) . flip (flip . ((.) .))) . (. ap (+)) . flip . ((flip . ((.) .)) .) . flip (.)) recurse))

-- splitChunks 1 [1,2,3,4,5]
-- [[1],[2],[3],[4],[5]]
-- splitChunks 2 [1,2,3,4,5]
-- [[1,2],[3,4],[5]]
splitChunks :: Int -> [a] -> [[a]]
splitChunks = (fix ((ap (flip if' ([]) . null) .) . (`ap` splitAt) . (((.) . liftM2 (:) fst) .) . flip flip snd . ((.) .)))

-- temp14
--   :: (a -> b1 -> [b2])
--      -> a -> b1 -> (b2 -> [[Int]]) -> ([Integer] -> Integer) -> Integer
-- temp14 = ((flip . temp21 . flip temp22) .)
temp14 a b c d e = temp23 (a b) d c e

-- temp23
--   :: (b1 -> [b2])
--      -> (b2 -> [[Int]]) -> b1 -> ([Integer] -> Integer) -> Integer
-- temp23 = temp21 . flip temp22
-- temp23 x y z w = temp21 ((\b -> temp22 b x)) y z w
-- temp23 x y z w = w (map (\x -> w (map fromIntegral x)) ((\b -> temp22 b x) y z))
temp23 x y z w = w (map (\x -> w (map fromIntegral x)) (temp22 y x z))

-- temp21
--   :: (a -> b -> [[Int]])
--      -> a -> b -> ([Integer] -> Integer) -> Integer
-- temp21 = ((flip . flip ((.) . ap (.) (map . (. map fromIntegral)))) .)
temp21 a b c d = d (map (\x -> d (map fromIntegral x)) (a b c))

-- temp22 :: (b -> [c]) -> (a -> [b]) -> a -> [c]
-- temp22 = ((.) . flip zipWith [0..] . flip . ((!!) .))
-- temp22 a = ((\b -> ((.) . flip zipWith [0..]) (flip b)) ((!!) . a))
-- temp22 a = ((.) . flip zipWith [0..]) (flip ((!!) . a))
-- temp22 a = (\b -> (.) (flip zipWith [0..] b)) (flip ((!!) . a))
-- temp22 a = (\b c -> (.) (zipWith b [0..]) c) (flip ((!!) . a))
-- temp22 a b = (.) (zipWith (flip ((!!) . a)) [0..]) b
-- temp22 a b c = zipWith (flip ((!!) . a)) [0..] (b c)
temp22 a b c = zipWith (flip (\x -> (!!) (a x))) [0..] (b c)
temp22 a b c = zipWith (\y z -> (\x -> (!!) (a x)) z y) [0..] (b c)

-- temp7 :: (a -> Int -> [Int]) -> a -> Int -> Integer
-- temp7 = (ap temp8 .)
-- temp7 x y z = temp8 z (x y z)

-- temp7 x y z = (temp8 (x y z)) y z
temp7 x y z = temp8 (x y) y

-- temp6 = ((flip . temp7) .)
-- temp2 x y z w = temp6 x y z w
temp2 x y z w = temp7 (x y) w z

-- mapModLength x y: for each element in y, % length of x
-- mapModLength [0,0] [1,2,3]
-- [1,0,1]
mapModLength :: [a] -> [Integer] -> [Int]
mapModLength = map . (fromIntegral .) . flip rem . toInteger . length

-- temp4
-- :: [b1] -> (a1 -> b2) -> a1 -> (a2 -> b2 -> [Int]) -> a2 -> [b1]
-- temp4 = (.) . flip . (flip .) . (.) . (.) . map . (!!)
temp4 a b c d e = map (\idx -> a !! idx) (d e (b c)) 

-- temp5 :: [b] -> [Integer] -> (a -> [Int] -> [Int]) -> a -> [b]
temp5 = ap temp4 mapModLength
-- temp5 x y z w = temp4 x (mapModLength x) y z w
-- temp5 x y z w = map (\idx -> x !! idx) (z w (mapModLength x y))

-- temp9 x y z = temp5 x y z (length x)
-- temp9 :: [a] -> [Integer] -> (Int -> [Int] -> [Int]) -> [a]
temp9 x y z = map (\idx -> x !! idx) (z (length x) (mapModLength x y))

-- temp1 :: [Int] -> Int -> [Integer] -> (Int -> [Int] -> [Int]) -> Integer
-- temp1 x y z w = (temp2 . temp5) x z y w
-- part2 = ap temp1 length
-- part2 :: [Int] -> [Integer] -> (Int -> [Int] -> [Int]) -> Integer
-- part2 x y z = temp1 x (length x) y z
-- part2 x y z = (temp2 . temp5) x y (length x) z
-- part2 x y z = temp2 (temp5 x) y (length x) z
-- part2 x y z = temp7 ((temp5 x) y) z (length x)
-- part2 x y z = temp7 (temp5 x y) z (length x)
-- part2 x y z = temp8 (length x) (temp9 x y z)

-- computeFlag x = (part1 . part2) x tribonacci
computeFlag :: [Int] -> Integer
-- computeFlag x = part1 (part2 x) tribonacci
-- computeFlag x = part2 x tribonacci getPrefixUntilUniqCountTo
computeFlag x = temp8 (length x) (temp9 x tribonacci getPrefixUntilUniqCountTo)
-- computeFlag x = temp8 (length x) (getElementsByTribonacci x)
-- computeFlag x = temp15 (temp20 (length x)) (getElementsByTribonacci x)
-- computeFlag x = temp20 (length x) (getElementsByTribonacci x) (temp11 insertTo) transformArrayToInt
-- computeFlag x = transformArrayToInt (step3 x)

-- (fix recurseFunction): generate permutation
recurseFunction recurse c = if' (null c) [([])]
    (if' (1 == (length c)) (return (return ((head c))))
        ((recurse (tail c) >>= ((\x -> map (\e -> (insertTo e x) (head c)) (enumFromTo 0 (length x)))))))

step1 x = splitChunks (length x) (getElementsByTribonacci x)
step2 x = zipWith (\y z -> (!!) (((fix recurseFunction) z)) y) [0..] (step1 x)
step3 x = map (\y -> transformArrayToInt (map fromIntegral y)) (step2 x)

getElementsByTribonacci :: [a] -> [a]
getElementsByTribonacci x = map (\idx -> x !! idx) (getPrefixUntilUniqCountTo (length x) (mapModLength x tribonacci))
checkFlag2 = (9808081677743135172288409775188158796289815169603605322273727506636905106808987096987267047244859212186619239940023129609388059687300704940688943841969983867118828709966912736034579721516747709253350210 ==) . computeFlag

computeFlagOrig = flip (flip flip ((takeUntilFirstFalse .) . checkPrefixUniqueCountLower)
    . ap (flip . 
        ((flip . (ap (temp15 . temp20) .)) .) . temp5) length)
    tribonacci 

main = do
    print $ getElementsByTribonacci $ map ord "abcd"
    print $ step1 $ map ord "abcd"
    print $ step2 $ map ord "abcd"
    print $ step3 $ map ord "abcd"
    print $ computeFlag $ map ord "abcd"
    print $ checkFlag $ map ord "\x00"
    print $ checkFlag2 $ map ord "\x00"
```
