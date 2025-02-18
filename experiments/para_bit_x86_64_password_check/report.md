# Experiment SINGLE_BIT on password_check.o with target Target.X86_64


## Settings 
- **program_file**: /home/dblshot/ghPackages/FaultSim/experiments/para_bit_x86_64_password_check/password_check.o
- **out_dir**: /home/dblshot/ghPackages/FaultSim/experiments/para_bit_x86_64_password_check/mutated_bins
- **program_input**:`['w', 'r', 'o', 'n', 'g', '\n']`
- **expected_stdout**:`['C', 'o', 'r', 'r', 'e', 'c', 't']`
- **expected_returncode**: 0
- **list_expected**: False
- **timeout**: 4
- **save_results**: /home/dblshot/ghPackages/FaultSim/experiments/para_bit_x86_64_password_check/results.csv
- **yes**: True


#### Binary information + Running the binary information
- Contains **123** instructions
- Therefore, FaultSim attempted to make **123** mutations
- Of the **123** attempted mutations, **3007** valid mutated binaries were generated
- The target arch was Target.X86_64
- The compile command was: `gcc test_files/password_check.c -o experiments/para_bit_x86_64_password_check/password_check.o`
- An example run command: `timeout 4s /home/dblshot/ghPackages/FaultSim/experiments/para_bit_x86_64_password_check/password_check.o`
- The NOP for this binary is: `Nop.X86_64`
- The runtime to generate and run binaries was: 0:00:10.129862


## Return Code Frequencies 
$$
\begin{array}{|c|c|}
\hline
Exit code & Frequency\\ \hline
\text{password denied (97)} & 1841 \\ \hline
\text{EX SIGSEGV (139)} & 936 \\ \hline
\text{EX SIGABRT (134)} & 121 \\ \hline
\text{password accepted (0)} & 43 \\ \hline
\text{Exit 0 : Bad STDOUT} & 1 \\ \hline
\text{EX SIGILL (132)} & 32 \\ \hline
\text{failed to run (-900)} & 8 \\ \hline
\text{133} & 7 \\ \hline
\text{135} & 4 \\ \hline
\text{6} & 3 \\ \hline
\text{124} & 2 \\ \hline
\text{7} & 1 \\ \hline
\text{225} & 1 \\ \hline
\text{33} & 1 \\ \hline
\text{EX DATAERR (65)} & 1 \\ \hline
\text{113} & 1 \\ \hline
\text{105} & 1 \\ \hline
\text{101} & 1 \\ \hline
\text{99} & 1 \\ \hline
\text{96} & 1 \\ \hline
\end{array}
$$


## Programs that ran critical code 
**43** programs ran the critical code out of **3007** mutated binaries. The binaires were:
- password_check.o_0x123d_24
- password_check.o_0x123d_25
- password_check.o_0x123d_26
- password_check.o_0x123d_27
- password_check.o_0x123d_28
- password_check.o_0x123d_29
- password_check.o_0x123d_30
- password_check.o_0x123d_31
- password_check.o_0x1248_29
- password_check.o_0x1248_31
- password_check.o_0x12a0_19
- password_check.o_0x12a3_19
- password_check.o_0x12a3_23
- password_check.o_0x12ab_10
- password_check.o_0x12ab_11
- password_check.o_0x12ab_13
- password_check.o_0x12ab_14
- password_check.o_0x12ad_7
- password_check.o_0x12ad_13
- password_check.o_0x12a6_9
- password_check.o_0x12c9_1
- password_check.o_0x12c9_14
- password_check.o_0x12c9_16
- password_check.o_0x12c9_17
- password_check.o_0x12c9_18
- password_check.o_0x12c9_19
- password_check.o_0x12c9_20
- password_check.o_0x12c9_21
- password_check.o_0x12c9_22
- password_check.o_0x12c9_23
- password_check.o_0x12c9_24
- password_check.o_0x12c9_25
- password_check.o_0x12c9_26
- password_check.o_0x12c9_27
- password_check.o_0x12c9_28
- password_check.o_0x12c9_29
- password_check.o_0x12c9_30
- password_check.o_0x12c9_31
- password_check.o_0x12cd_1
- password_check.o_0x12cd_4
- password_check.o_0x12cd_5
- password_check.o_0x12cd_7
- password_check.o_0x12e5_28


#### Program 0 password_check.o_0x123d_24 diassemebly vs vanilla

```
0|0x1233 b8 00 00 00 00         mov eax, 0                       |0x1233 b8 00 00 00 00         mov eax, 0                       |
1|0x1238 e8 a3 fe ff ff         call 0x10e0                      |0x1238 e8 a3 fe ff ff         call 0x10e0                      |
2|0x123d c6 45 ec 00            mov byte ptr [rbp - 0x14], 0     |0x123d c6 45 ec 80            mov byte ptr [rbp - 0x14], 0x80  |
3|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
```


#### Program 1 password_check.o_0x123d_25 diassemebly vs vanilla

```
0|0x1233 b8 00 00 00 00         mov eax, 0                       |0x1233 b8 00 00 00 00         mov eax, 0                       |
1|0x1238 e8 a3 fe ff ff         call 0x10e0                      |0x1238 e8 a3 fe ff ff         call 0x10e0                      |
2|0x123d c6 45 ec 00            mov byte ptr [rbp - 0x14], 0     |0x123d c6 45 ec 40            mov byte ptr [rbp - 0x14], 0x40  |
3|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
```


#### Program 2 password_check.o_0x123d_26 diassemebly vs vanilla

```
0|0x1233 b8 00 00 00 00         mov eax, 0                       |0x1233 b8 00 00 00 00         mov eax, 0                       |
1|0x1238 e8 a3 fe ff ff         call 0x10e0                      |0x1238 e8 a3 fe ff ff         call 0x10e0                      |
2|0x123d c6 45 ec 00            mov byte ptr [rbp - 0x14], 0     |0x123d c6 45 ec 20            mov byte ptr [rbp - 0x14], 0x20  |
3|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
```


#### Program 3 password_check.o_0x123d_27 diassemebly vs vanilla

```
0|0x1233 b8 00 00 00 00         mov eax, 0                       |0x1233 b8 00 00 00 00         mov eax, 0                       |
1|0x1238 e8 a3 fe ff ff         call 0x10e0                      |0x1238 e8 a3 fe ff ff         call 0x10e0                      |
2|0x123d c6 45 ec 00            mov byte ptr [rbp - 0x14], 0     |0x123d c6 45 ec 10            mov byte ptr [rbp - 0x14], 0x10  |
3|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
```


#### Program 4 password_check.o_0x123d_28 diassemebly vs vanilla

```
0|0x1233 b8 00 00 00 00         mov eax, 0                       |0x1233 b8 00 00 00 00         mov eax, 0                       |
1|0x1238 e8 a3 fe ff ff         call 0x10e0                      |0x1238 e8 a3 fe ff ff         call 0x10e0                      |
2|0x123d c6 45 ec 00            mov byte ptr [rbp - 0x14], 0     |0x123d c6 45 ec 08            mov byte ptr [rbp - 0x14], 8     |
3|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
```


#### Program 5 password_check.o_0x123d_29 diassemebly vs vanilla

```
0|0x1233 b8 00 00 00 00         mov eax, 0                       |0x1233 b8 00 00 00 00         mov eax, 0                       |
1|0x1238 e8 a3 fe ff ff         call 0x10e0                      |0x1238 e8 a3 fe ff ff         call 0x10e0                      |
2|0x123d c6 45 ec 00            mov byte ptr [rbp - 0x14], 0     |0x123d c6 45 ec 04            mov byte ptr [rbp - 0x14], 4     |
3|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
```


#### Program 6 password_check.o_0x123d_30 diassemebly vs vanilla

```
0|0x1233 b8 00 00 00 00         mov eax, 0                       |0x1233 b8 00 00 00 00         mov eax, 0                       |
1|0x1238 e8 a3 fe ff ff         call 0x10e0                      |0x1238 e8 a3 fe ff ff         call 0x10e0                      |
2|0x123d c6 45 ec 00            mov byte ptr [rbp - 0x14], 0     |0x123d c6 45 ec 02            mov byte ptr [rbp - 0x14], 2     |
3|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
```


#### Program 7 password_check.o_0x123d_31 diassemebly vs vanilla

```
0|0x1233 b8 00 00 00 00         mov eax, 0                       |0x1233 b8 00 00 00 00         mov eax, 0                       |
1|0x1238 e8 a3 fe ff ff         call 0x10e0                      |0x1238 e8 a3 fe ff ff         call 0x10e0                      |
2|0x123d c6 45 ec 00            mov byte ptr [rbp - 0x14], 0     |0x123d c6 45 ec 01            mov byte ptr [rbp - 0x14], 1     |
3|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
```


#### Program 8 password_check.o_0x1248_29 diassemebly vs vanilla

```
0|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
1|0x1248 48 8d 45 ed            lea rax, [rbp - 0x13]            |0x1248 48 8d 45 e9            lea rax, [rbp - 0x17]            |
2|0x124c be 0b 00 00 00         mov esi, 0xb                     |0x124c be 0b 00 00 00         mov esi, 0xb                     |
3|0x1251 48 89 c7               mov rdi, rax                     |0x1251 48 89 c7               mov rdi, rax                     |
```


#### Program 9 password_check.o_0x1248_31 diassemebly vs vanilla

```
0|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|0x1241 48 8b 15 c8 2d 00 00   mov rdx, qword ptr [rip + 0x2dc8]|
1|0x1248 48 8d 45 ed            lea rax, [rbp - 0x13]            |0x1248 48 8d 45 ec            lea rax, [rbp - 0x14]            |
2|0x124c be 0b 00 00 00         mov esi, 0xb                     |0x124c be 0b 00 00 00         mov esi, 0xb                     |
3|0x1251 48 89 c7               mov rdi, rax                     |0x1251 48 89 c7               mov rdi, rax                     |
```


#### Program 10 password_check.o_0x12a0_19 diassemebly vs vanilla

```
0|0x1299 48 8d 15 93 0d 00 00   lea rdx, [rip + 0xd93]|0x1299 48 8d 15 93 0d 00 00   lea rdx, [rip + 0xd93]|
1|0x12a0 48 89 d6               mov rsi, rdx          |0x12a0 48 89 c6               mov rsi, rax          |
2|0x12a3 48 89 c7               mov rdi, rax          |0x12a3 48 89 c7               mov rdi, rax          |
3|0x12a6 e8 65 fe ff ff         call 0x1110           |0x12a6 e8 65 fe ff ff         call 0x1110           |
```


#### Program 11 password_check.o_0x12a3_19 diassemebly vs vanilla

```
0|0x1299 48 8d 15 93 0d 00 00   lea rdx, [rip + 0xd93]|0x1299 48 8d 15 93 0d 00 00   lea rdx, [rip + 0xd93]|
1|0x12a0 48 89 d6               mov rsi, rdx          |0x12a0 48 89 d6               mov rsi, rdx          |
2|0x12a3 48 89 c7               mov rdi, rax          |0x12a3 48 89 d7               mov rdi, rdx          |
3|0x12a6 e8 65 fe ff ff         call 0x1110           |0x12a6 e8 65 fe ff ff         call 0x1110           |
4|0x12ab 85 c0                  test eax, eax         |0x12ab 85 c0                  test eax, eax         |
5|0x12ad 75 1a                  jne 0x12c9            |0x12ad 75 1a                  jne 0x12c9            |
```


#### Program 12 password_check.o_0x12a3_23 diassemebly vs vanilla

```
0|0x1299 48 8d 15 93 0d 00 00   lea rdx, [rip + 0xd93]|0x1299 48 8d 15 93 0d 00 00   lea rdx, [rip + 0xd93]|
1|0x12a0 48 89 d6               mov rsi, rdx          |0x12a0 48 89 d6               mov rsi, rdx          |
2|0x12a3 48 89 c7               mov rdi, rax          |0x12a3 48 89 c6               mov rsi, rax          |
3|0x12a6 e8 65 fe ff ff         call 0x1110           |0x12a6 e8 65 fe ff ff         call 0x1110           |
4|0x12ab 85 c0                  test eax, eax         |0x12ab 85 c0                  test eax, eax         |
5|0x12ad 75 1a                  jne 0x12c9            |0x12ad 75 1a                  jne 0x12c9            |
```


#### Program 13 password_check.o_0x12ab_10 diassemebly vs vanilla

```
0|0x12a3 48 89 c7               mov rdi, rax                |0x12a3 48 89 c7               mov rdi, rax                |
1|0x12a6 e8 65 fe ff ff         call 0x1110                 |0x12a6 e8 65 fe ff ff         call 0x1110                 |
2|0x12ab 85 c0                  test eax, eax               |0x12ab 85 e0                  test eax, esp               |
3|0x12ad 75 1a                  jne 0x12c9                  |0x12ad 75 1a                  jne 0x12c9                  |
4|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|
5|0x12b3 eb 14                  jmp 0x12c9                  |0x12b3 eb 14                  jmp 0x12c9                  |
6|0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |
```


#### Program 14 password_check.o_0x12ab_11 diassemebly vs vanilla

```
0|0x12a3 48 89 c7               mov rdi, rax                |0x12a3 48 89 c7               mov rdi, rax                |
1|0x12a6 e8 65 fe ff ff         call 0x1110                 |0x12a6 e8 65 fe ff ff         call 0x1110                 |
2|0x12ab 85 c0                  test eax, eax               |0x12ab 85 d0                  test eax, edx               |
3|0x12ad 75 1a                  jne 0x12c9                  |0x12ad 75 1a                  jne 0x12c9                  |
4|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|
5|0x12b3 eb 14                  jmp 0x12c9                  |0x12b3 eb 14                  jmp 0x12c9                  |
6|0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |
```


#### Program 15 password_check.o_0x12ab_13 diassemebly vs vanilla

```
0|0x12a3 48 89 c7               mov rdi, rax                |0x12a3 48 89 c7               mov rdi, rax                |
1|0x12a6 e8 65 fe ff ff         call 0x1110                 |0x12a6 e8 65 fe ff ff         call 0x1110                 |
2|0x12ab 85 c0                  test eax, eax               |0x12ab 85 c4                  test esp, eax               |
3|0x12ad 75 1a                  jne 0x12c9                  |0x12ad 75 1a                  jne 0x12c9                  |
4|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|
5|0x12b3 eb 14                  jmp 0x12c9                  |0x12b3 eb 14                  jmp 0x12c9                  |
6|0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |
```


#### Program 16 password_check.o_0x12ab_14 diassemebly vs vanilla

```
0|0x12a3 48 89 c7               mov rdi, rax                |0x12a3 48 89 c7               mov rdi, rax                |
1|0x12a6 e8 65 fe ff ff         call 0x1110                 |0x12a6 e8 65 fe ff ff         call 0x1110                 |
2|0x12ab 85 c0                  test eax, eax               |0x12ab 85 c2                  test edx, eax               |
3|0x12ad 75 1a                  jne 0x12c9                  |0x12ad 75 1a                  jne 0x12c9                  |
4|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|
5|0x12b3 eb 14                  jmp 0x12c9                  |0x12b3 eb 14                  jmp 0x12c9                  |
6|0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |
```


#### Program 17 password_check.o_0x12ad_7 diassemebly vs vanilla

```
0|0x12a3 48 89 c7               mov rdi, rax                |0x12a3 48 89 c7               mov rdi, rax                |
1|0x12a6 e8 65 fe ff ff         call 0x1110                 |0x12a6 e8 65 fe ff ff         call 0x1110                 |
2|0x12ab 85 c0                  test eax, eax               |0x12ab 85 c0                  test eax, eax               |
3|0x12ad 75 1a                  jne 0x12c9                  |0x12ad 74 1a                  je 0x12c9                   |
4|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|
5|0x12b3 eb 14                  jmp 0x12c9                  |0x12b3 eb 14                  jmp 0x12c9                  |
6|0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |
```


#### Program 18 password_check.o_0x12ad_13 diassemebly vs vanilla

```
0|0x12a3 48 89 c7               mov rdi, rax                |0x12a3 48 89 c7               mov rdi, rax                |
1|0x12a6 e8 65 fe ff ff         call 0x1110                 |0x12a6 e8 65 fe ff ff         call 0x1110                 |
2|0x12ab 85 c0                  test eax, eax               |0x12ab 85 c0                  test eax, eax               |
3|0x12ad 75 1a                  jne 0x12c9                  |0x12ad 75 1e                  jne 0x12cd                  |
4|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|0x12af c6 45 ec 01            mov byte ptr [rbp - 0x14], 1|
5|0x12b3 eb 14                  jmp 0x12c9                  |0x12b3 eb 14                  jmp 0x12c9                  |
6|0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |0x12b5 48 8d 05 7c 0d 00 00   lea rax, [rip + 0xd7c]      |
```


#### Program 19 password_check.o_0x12a6_9 diassemebly vs vanilla

```
0|0x12a0 48 89 d6         mov rsi, rdx                |0x12a0 48 89 d6         mov rsi, rdx                |
1|0x12a3 48 89 c7         mov rdi, rax                |0x12a3 48 89 c7         mov rdi, rax                |
2|0x12a6 e8 65 fe ff ff   call 0x1110                 |0x12a6 e8 25 fe ff ff   call 0x10d0                 |
3|0x12ab 85 c0            test eax, eax               |0x12ab 85 c0            test eax, eax               |
4|0x12ad 75 1a            jne 0x12c9                  |0x12ad 75 1a            jne 0x12c9                  |
5|0x12af c6 45 ec 01      mov byte ptr [rbp - 0x14], 1|0x12af c6 45 ec 01      mov byte ptr [rbp - 0x14], 1|
```


#### Program 20 password_check.o_0x12c9_1 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 c0 7d ec 00            sar byte ptr [rbp - 0x14], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 21 password_check.o_0x12c9_14 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7f ec 00            cmp byte ptr [rdi - 0x14], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 22 password_check.o_0x12c9_16 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d 6c 00            cmp byte ptr [rbp + 0x6c], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 23 password_check.o_0x12c9_17 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ac 00            cmp byte ptr [rbp - 0x54], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 24 password_check.o_0x12c9_18 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d cc 00            cmp byte ptr [rbp - 0x34], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 25 password_check.o_0x12c9_19 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0               |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0              |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d fc 00            cmp byte ptr [rbp - 4], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]   |
```


#### Program 26 password_check.o_0x12c9_20 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d e4 00            cmp byte ptr [rbp - 0x1c], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 27 password_check.o_0x12c9_21 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d e8 00            cmp byte ptr [rbp - 0x18], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 28 password_check.o_0x12c9_22 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ee 00            cmp byte ptr [rbp - 0x12], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 29 password_check.o_0x12c9_23 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ed 00            cmp byte ptr [rbp - 0x13], 0|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 30 password_check.o_0x12c9_24 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                     |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                    |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 80            cmp byte ptr [rbp - 0x14], 0x80|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                      |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]         |
```


#### Program 31 password_check.o_0x12c9_25 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                     |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                    |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 40            cmp byte ptr [rbp - 0x14], 0x40|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                      |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]         |
```


#### Program 32 password_check.o_0x12c9_26 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                     |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                    |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 20            cmp byte ptr [rbp - 0x14], 0x20|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                      |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]         |
```


#### Program 33 password_check.o_0x12c9_27 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                     |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                    |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 10            cmp byte ptr [rbp - 0x14], 0x10|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                      |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]         |
```


#### Program 34 password_check.o_0x12c9_28 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 08            cmp byte ptr [rbp - 0x14], 8|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 35 password_check.o_0x12c9_29 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 04            cmp byte ptr [rbp - 0x14], 4|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 36 password_check.o_0x12c9_30 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 02            cmp byte ptr [rbp - 0x14], 2|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 37 password_check.o_0x12c9_31 diassemebly vs vanilla

```
0|0x12bf b8 00 00 00 00         mov eax, 0                  |0x12bf b8 00 00 00 00         mov eax, 0                  |
1|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
2|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 01            cmp byte ptr [rbp - 0x14], 1|
3|0x12cd 74 16                  je 0x12e5                   |0x12cd 74 16                  je 0x12e5                   |
4|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
```


#### Program 38 password_check.o_0x12cd_1 diassemebly vs vanilla

```
0|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
1|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|
2|0x12cd 74 16                  je 0x12e5                   |0x12cd 34 16                  xor al, 0x16                |
3|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
4|0x12d6 48 89 c7               mov rdi, rax                |0x12d6 48 89 c7               mov rdi, rax                |
```


#### Program 39 password_check.o_0x12cd_4 diassemebly vs vanilla

```
0|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
1|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|
2|0x12cd 74 16                  je 0x12e5                   |0x12cd 7c 16                  jl 0x12e5                   |
3|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
4|0x12d6 48 89 c7               mov rdi, rax                |0x12d6 48 89 c7               mov rdi, rax                |
```


#### Program 40 password_check.o_0x12cd_5 diassemebly vs vanilla

```
0|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
1|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|
2|0x12cd 74 16                  je 0x12e5                   |0x12cd 70 16                  jo 0x12e5                   |
3|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
4|0x12d6 48 89 c7               mov rdi, rax                |0x12d6 48 89 c7               mov rdi, rax                |
```


#### Program 41 password_check.o_0x12cd_7 diassemebly vs vanilla

```
0|0x12c4 e8 17 fe ff ff         call 0x10e0                 |0x12c4 e8 17 fe ff ff         call 0x10e0                 |
1|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|0x12c9 80 7d ec 00            cmp byte ptr [rbp - 0x14], 0|
2|0x12cd 74 16                  je 0x12e5                   |0x12cd 75 16                  jne 0x12e5                  |
3|0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |0x12cf 48 8d 05 6b 0d 00 00   lea rax, [rip + 0xd6b]      |
4|0x12d6 48 89 c7               mov rdi, rax                |0x12d6 48 89 c7               mov rdi, rax                |
```


#### Program 42 password_check.o_0x12e5_28 diassemebly vs vanilla

```
0|0x12de b8 00 00 00 00         mov eax, 0            |0x12de b8 00 00 00 00         mov eax, 0            |
1|0x12e3 eb 14                  jmp 0x12f9            |0x12e3 eb 14                  jmp 0x12f9            |
2|0x12e5 48 8d 05 5d 0d 00 00   lea rax, [rip + 0xd5d]|0x12e5 48 8d 05 55 0d 00 00   lea rax, [rip + 0xd55]|
3|0x12ec 48 89 c7               mov rdi, rax          |0x12ec 48 89 c7               mov rdi, rax          |
4|0x12ef e8 bc fd ff ff         call 0x10b0           |0x12ef e8 bc fd ff ff         call 0x10b0           |
```




## Source Code Lines
```c
#include <stdio.h>
#include <stdlib.h>  // Required for the exit() function
#include <stdbool.h> 
#include <string.h>
// Below provides "EXIT_SUCCESS"
#include <stdbool.h>

// Correct password:
#define PASSWORD "pass" 

// Password input max length:
#define MAX_LENGTH 10

/*
* int main
*   A sample program to that has a user enter a password and sees if it's correct
*/
int main() {

    // Buffer to store user input (extra byte for null terminator)
    char input[MAX_LENGTH + 1];  
    printf("Enter the password (max %d characters): ", MAX_LENGTH);

    bool password_correct = false;

    // fgets takes arguments: (buffer, buffer_size, input) 
    // this assures that the input is no longer than the size of the buffer
    if (fgets(input, sizeof(input), stdin) != NULL) {
        // If the entered password exceeds the 
        // buffer it's incorrect
        if (strchr(input, '\n') == NULL) {
            password_correct = false;
        }
        else {
            // Remove the newling character
            input[strcspn(input, "\n")] = '\0';

            // NOTICE: fgets and strchr make sure the passowrd
            //      is the correct length so strcmp is safe :)
            if (strcmp(input, PASSWORD) == 0) {
                password_correct = true;
            }
        }
    }
    else {
        printf("no input");
    }


    // Compare the input with the predefined password
    if (password_correct == 1)  {
        printf("Correct\n");
        // Exit with 0 when exit is correct!
        return EXIT_SUCCESS;
    } else {
        printf("Wrong\n");
        return 97;
    }

    return 84;
}

```
