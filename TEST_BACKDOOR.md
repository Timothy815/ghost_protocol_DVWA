# Temporary Flag Backdoor (disabled)

We previously allowed a universal override `12345` for testing. It is now **removed**.

To re-enable temporarily (and remember to remove before shipping):
1) Edit `ghost_protocol.html`, in `submitFlag()` add:
```js
// Temporary testing backdoor: accept universal override '12345'
const backdoor = (input === '12345');
const isCorrect = backdoor || (typeof m.flagCheck === 'function'
    ? m.flagCheck(input)
    : input === m.flag);
```
2) When done testing, remove the backdoor lines and revert to the normal `isCorrect` assignment:
```js
const isCorrect = typeof m.flagCheck === 'function'
    ? m.flagCheck(input)
    : input === m.flag;
```

Commit guidance: keep the backdoor out of committed code unless explicitly testing.***
