
### Description:
```
Every object allocated lives somewhere. The flag was never sent to you — but it's already in your browser. Take a snapshot. Dig deeper.
```

<img width="1904" height="901" alt="image" src="https://github.com/user-attachments/assets/65631300-e05e-4367-abfc-093ecff4e8e3" />

___
This is a classic Web/Client-side Forensics challenge. The title "Heap of Secrets" and the description are giving you the literal roadmap to the flag.

The key phrase is: "The flag was never sent to you — but it's already in your browser. Take a snapshot. Dig deeper."
___
In web development, "Heap" and "Snapshot" refer to Memory Profiling. The challenge is telling you that the flag exists as a string or object within the JavaScript memory (the heap) of the page, even if it isn't rendered in the HTML or visible in the Network tab.

**How to solve this:**

1. Open Developer Tools: Press `F12` or `Ctrl+Shift+I` (Cmd+Option+I on Mac) on the challenge page.

2. Go to the "Memory" Tab: This is usually located next to "Network" or "Application."

3. Take a Heap Snapshot:

* Select the "Heap snapshot" radio button.

* Click the "Take snapshot" button (the blue circle or "Record" icon).

<img width="1047" height="887" alt="image" src="https://github.com/user-attachments/assets/bcf1c41e-f9c6-4829-8c2a-114f431b5a32" />

* Wait a few seconds for the browser to map out every object currently stored in the page's RAM.

4. Search the Snapshot:

* Once the snapshot is loaded, click inside the results and press Ctrl+F (or Cmd+F).

* Search for the flag prefix: VishwaCTF.

* This should highlight a string or a variable containing the full flag.

<img width="1049" height="882" alt="image" src="https://github.com/user-attachments/assets/4fce360c-7d10-4b9c-9093-f252d4d27200" />

___

Often in "Single Page Applications" (like the "NodeWatch" dashboard in your screenshot), developers might fetch data or hardcode configuration objects that contain sensitive info. Even if that info isn't "printed" on the screen, it stays in the browser's memory as long as the tab is open. A Heap Snapshot allows you to look at the "brain" of the page to find these hidden strings.
