# onetimepad

This challenge fits into the category of babyheap challenges which are small heap puzzles with arbitrary limitations. Here a small pad was implemented with could hold eight notes at a time but after reading a note it was destroyed. The vulnerability was a classical use after free (UAF) in `rewrite` that did not check wether a note was valid or not. This bug however could only be triggered once.

-:|:-
target | `88.198.154.140 31336`
flag | `hxp{HsIuUU__g-will-5e1f-d3s7rUct-af7er-R3adlnG}`
full disclosure | I am the author

please forgive me for the meta joke in the flag. The first eight characters should look like a (ascii) heap address.

## Exploit path

The UAF can be used to corrupt the free lists of glibcs malloc. Only sorted and unsorted bins may point to the libc which are subject to a bunch of sanity checks directly going for the free hook is not possible. Additionally we would not know what to write there as no free leak comes with this challenge. So instead we go for a generic solution: Gain persistent control over a chunk header, specifically the size field and the pointers. Since input is copied to the heap via `strcpy` i try to crete such scenario by writing only the empty string. Writing more bytes would overwrite some byte affected by `ASLR` resulting in worse exploit performance.

```
4f0     500     510             530
─┼───────┼───────┼───────────────┼────
 │ 0     ┊<fake> │ 1             │ 2
─┴───┬───┴───────┴───────────────┴────
     4f8  ▲        │
          ╰────────╯
```
To gain control over a chunk by only overwriting the lowest address with a null byte I arange the heap like displayed above. I then free `B` and `A` in that order and use my one `UAF` to change the `tcache` pointer in `1` to point to a fake chunk directly infront of it. Please note that the forward pointer of `tcaches` points to the chunks data, not the struct beginning. The second allocation now returns the fake chunk at offset `500`. We now can control the chunk at `510` with our fake chunk and also change the fake chunk struct with our note `0`. As we can not rewrite notes any more the persistent control is implemented by freeing and then allocating that chunk again.

Next we want to generate a leak. After printing a note the chunk will be freed and since version `2.28` a simple double free protection was implemented for `tcaches`, therfor we have to do some additional trickery. If we take a look at that consistency check we see, that it triggers when the second pointer in the chunk points to the threads `tcache` management _and_ the pointer is already in the list of cached chunks _for that size_. Since this is a single threaded application the second check seems as the way to go. To circumvent that check we have to change the size field of the chunk we want to leak between both reads. With that said, we first need to set up the heap so two notes point to the same memory. I thought writing a `null` byte into the `tcache nxt` pointer is easy and yields very consistent results and we already have one chunk at `500` we use the same trick again.
```
(not to scale)
4f0     500     510  530 550     590
─┼───────┼───────┼───┼───┼───────┼───
 │ 0     ┊<fake> │ 1 │ 2 │       │ 3
─┴───┬───┴───────┴───┴───┴───────┴───
     4f8  ▲        │               │
          ├────────╯               │
          ╰────────────────────────╯
```
For convinience the size of the second chunk was choosen to be `90`, a size large enough to later be handled by `unsorted bins` and leaking a `libc` address. As I cannot use `rewrite` any more i need to place the forward pointer at a location I control. So I change the chunk of `1` to be of `90` size by overflowing from the fake chunk. As eight notes are just enough to fill up the `tcaches` and have one additional free, the used chunks have to be juggled a bit. Additionally before freeing the last chunk (at address `500`) we need to hold a second _active_ allocation to that chunk, as adding a note later would write a `null` byte and destroy the leak. We can now generate the leak by:
1. reading the note at `500` (chunk size `90`)
2. overwriting the chunk header of `500` by `ghetto-rewriting` `0`
3. reading the note at `500` again (chunk size `20`)

From now on this is a genric `tcache` poison exploit. We know the location of the libc and have control over a `tcache` forward pointer from the previous steps. I went for the good old classic `__free_hook`.