# Como funciona o hexray

*[English version](how-it-works.md)*

Uma explicação passo a passo do que o hexray faz e de como o código o faz, para quem já sabe o básico de C. Para as opções de cada comando, vê o [README](../README.md).

## A ideia geral

Imagina um email com um anexo chamado `invoice.pdf`. Podias abri-lo para ver o que faz, mas se for malware, o computador já ficou infetado.

O hexray responde à pergunta **"o que é este ficheiro?" sem nunca o executar**. Só lê os bytes, como quem lê um texto. A isto chama-se análise estática.

Um ficheiro é apenas uma sequência de números de 0 a 255. Cada comando do hexray olha para esses números de uma maneira diferente:

| Comando | A pergunta a que responde |
|---|---|
| `dump` | Que bytes estão aqui? |
| `type` | Que tipo de ficheiro é isto na realidade? |
| `strings` | Há texto legível lá dentro? |
| `entropy` | Está a esconder alguma coisa? |
| `hash` | Alguém já viu este ficheiro? |
| `headers` | O que é que este programa pede ao sistema? |
| `scan` | Parece-se com algo que já conheço? |

## Como o código está organizado

| Onde | O que faz |
|---|---|
| `src/main.c` | Lê a primeira palavra que escreveste e chama o comando certo, através de uma tabela de ponteiros para funções |
| `src/dump.c`, `type.c`, `strscan.c`, `entropy.c`, `hash.c`, `headers.c`, `scan.c` | Um ficheiro por comando |
| `src/sha256.c` | O algoritmo SHA-256, separado do comando que o usa |
| `src/binary.c`, `pe.c`, `elf.c` | A leitura segura de ficheiros não confiáveis e os dois formatos de executáveis |
| `src/util.c` | Pequenas funções partilhadas por vários comandos |
| `tests/` | Um script por comando, executados pelo `make test` |
| `rules/starter.rules` | Um pequeno conjunto de assinaturas para o `scan` |

A `Makefile` compila duas versões. O `build/hexray` é a normal. O `build/debug/hexray` inclui o AddressSanitizer e o UndefinedBehaviorSanitizer, que param o programa quando este comete um erro de memória. Os testes correm nas duas.

Para acompanhares as experiências abaixo, compila primeiro:

```bash
make
```

## 1. `dump`: mostrar os bytes

**A ideia.** Lê 16 bytes de cada vez e imprime cada linha com o offset, os bytes em hexadecimal e os mesmos bytes como texto. Os bytes que não se podem imprimir aparecem como `.`. As linhas repetidas são substituídas por um único `*`.

**Lê em `dump.c`.** Começa pelo `dump()`, o ciclo principal, e depois o `print_line()`. A seguir, o `parse_options()` mostra como funciona o `getopt`.

**C que vais encontrar.** `fread`, `structs`, funções `static`, formatos de `printf` como `%02x`, e `memcmp`.

**Experimenta.**

```bash
build/hexray dump -n 64 README.md
```

**Testa-te.**
- Porque é que o código guarda o `previous_count` e não apenas o array `previous`?
- Porque é que `-n 0` tem de ser guardado de forma diferente de "não foi dado `-n`"?
- Porque é que o `skip_bytes()` lê e deita fora os dados em vez de usar `fseek`?

## 2. `type`: o que é este ficheiro na realidade?

**A ideia.** A maioria dos formatos começa com bytes fixos, chamados *magic bytes*: um PDF começa por `%PDF` e um programa Windows por `MZ`. O sistema operativo não quer saber do nome do ficheiro, e os atacantes aproveitam isso. Se o `invoice.pdf` for na realidade um programa Windows, o hexray imprime `MISMATCH`.

Dois bytes são pouca prova, porque um texto pode começar por `MZ` por acaso. Por isso, o `is_pe()` segue também o ponteiro guardado no offset `0x3c` e confirma que está lá um cabeçalho PE real.

**Lê em `type.c`.** Primeiro a tabela `types[]`, depois `identify()`, `is_pe()`, `find_extension()` e `find_mismatch()`.

**C que vais encontrar.** Arrays de structs, ponteiros para funções (o campo `confirm`), deslocamentos de bits e números big-endian em `read_be32()`.

**Experimenta.**

```bash
build/hexray type /bin/ls README.md
```

**Testa-te.**
- Os binários universais e as classes Java começam pelos mesmos 4 bytes. Como é que o código os distingue?
- Porque é que `.bak` nunca é assinalado, mas `.pdf` pode ser?
- Porque é que `(uint32_t) bytes[0] << 24` precisa da conversão?

## 3. `strings`: encontrar texto legível

**A ideia.** Percorre o ficheiro e recolhe todas as sequências de caracteres imprimíveis. Um URL, um `cmd.exe` ou uma chave de registo podem denunciar o que um programa pretende fazer.

O Windows costuma guardar o texto em UTF-16, em que cada letra ocupa dois bytes: `H`, `0`, `e`, `0`. Procurar só ASCII deixaria isso escapar. Uma string UTF-16 pode começar num offset par ou ímpar, por isso o scanner segue os dois alinhamentos ao mesmo tempo. Cada byte é a segunda metade de uma unidade que começou no byte anterior.

**Lê em `strscan.c`.** O `process_byte()` é o núcleo. Depois `feed()`, `run_append()` e `run_finish()`. Por fim, `collect_flags()` com `has_ipv4()` e `has_base64_blob()`.

**C que vais encontrar.** `realloc` para aumentar um buffer, um ponteiro para ponteiro em `read_octet()`, e `%.*s`.

**Experimenta.**

```bash
build/hexray strings -f /usr/bin/curl
```

**Testa-te.**
- Porque é que o `run_append()` guarda primeiro o resultado do `realloc` numa variável nova?
- O que decide exatamente que uma sequência é Base64, e que falsos positivos elimina cada regra?
- Porque é que as etiquetas são calculadas sobre a string inteira, mesmo quando a saída a corta?

## 4. `entropy`: está a esconder alguma coisa?

**A ideia.** A entropia de Shannon mede quão imprevisíveis são os bytes, de 0 a 8 bits por byte. Bytes todos iguais dão 0. Os 256 valores igualmente frequentes dão 8. Código e texto ficam entre 4 e 6, e dados comprimidos ou cifrados ficam perto de 8.

O malware usa *packing*: o código real fica guardado cifrado e só é aberto quando o programa corre, por isso as ferramentas estáticas não encontram nada para ler. Um programa quase todo com entropia alta é suspeito. Um JPEG não é, porque é comprimido por natureza, e por isso o veredicto também olha para o tipo de ficheiro.

A fórmula é `H = -soma(p * log2(p))`, em que `p` é a fração dos bytes com um dado valor. Com dois valores, metade cada um: `-(0.5 * -1 + 0.5 * -1) = 1`.

**Lê em `entropy.c`.** `shannon_entropy()`, `finish_block()`, `update_packers()` e `verdict()`.

**C que vais encontrar.** `double`, converter antes de dividir, `log2`, ligar com `-lm`, e `memset`.

**Experimenta.**

```bash
build/hexray entropy -b 0x8000 /bin/ls
```

**Testa-te.**
- O que daria `counts[value] / total` sem a conversão para `double`?
- Porque é que um bloco muito pequeno nunca consegue ter entropia alta, mesmo que seja puro ruído?
- Porque é que uma assinatura dividida entre duas leituras é encontrada na mesma?

## 5. `hash`: alguém já viu este ficheiro?

**A ideia.** O SHA-256 transforma qualquer quantidade de dados numa impressão digital de 256 bits. Muda um bit à entrada e cerca de metade da saída muda. Podes pesquisar esse valor no VirusTotal ou no MalwareBazaar para saber se um ficheiro é conhecido, sem o enviar.

O algoritmo começa com 8 números fixos de 32 bits. Cada bloco de 64 bytes de dados mistura-os ao longo de 64 rondas de rotações, XOR e somas. Os 8 números finais são o hash.

**Lê em `sha256.c`.** `sha256_update()` para veres como os dados são divididos em blocos, `sha256_final()` para o padding, e depois `compress()`.

**C que vais encontrar.** `uint32_t`, overflow sem sinal, rotação de bits, `const void *`.

**Experimenta.** As duas linhas têm de imprimir o mesmo hash:

```bash
build/hexray hash README.md
```

```bash
shasum -a 256 README.md
```

**Testa-te.**
- Porque é que estas somas têm de usar tipos sem sinal?
- O que acrescenta o padding no fim da mensagem, e quando é que precisa de mais um bloco?
- Porque é que a interface está dividida em `init`, `update` e `final`?

## 6. `headers`: o que é que este programa pede?

**A ideia.** Um executável é como um livro com índice. As *secções* são os capítulos: código, dados, etc. Os *imports* são as funções que pede ao sistema operativo. Pedir `WriteProcessMemory` e `CreateRemoteThread` sugere injeção de código noutro processo.

**A ideia mais importante do projeto: tudo no ficheiro pode ser mentira.** Se um cabeçalho diz "a tabela está no byte 4 000 000 000" e o programa acredita, lê memória que não devia e pode rebentar ou ser explorado. Por isso, todas as leituras dos parsers passam pelo `src/binary.c`, que confirma primeiro se esses bytes existem mesmo.

**Como está organizado um ficheiro PE.**
1. O ficheiro começa por `MZ`, e os 4 bytes em `0x3c` dizem onde está o cabeçalho PE real.
2. A seguir vêm o cabeçalho COFF, o cabeçalho opcional e a tabela de secções.
3. O cabeçalho opcional diz onde está a tabela de imports, como RVA: um endereço na memória, não no ficheiro. O `rva_to_offset()` traduz esse endereço com a ajuda da tabela de secções.
4. Cada entrada dos imports indica uma DLL e leva à sua lista de funções.

**O ELF é mais simples.** Um cabeçalho aponta para a tabela de secções, e as funções importadas são os símbolos marcados como indefinidos em `.dynsym`.

**Lê, por esta ordem.** `binary.c` (começa por `reader_has()` e depois `reader_string()`), `pe.c` (`pe_parse()`, `rva_to_offset()`, `read_imports()`, `read_thunks()`), `elf.c` (`elf_parse()`) e `headers.c` (`analyse()`, `flag_for_import()`).

**C que vais encontrar.** Overflow de inteiros em verificações de limites, little e big endian, e ponteiros mantidos dentro de um buffer.

**Experimenta.** O macOS não tem ficheiros ELF nem PE nas pastas do sistema, por isso usa os ficheiros de teste, que são inofensivos:

```bash
rm -rf build/fixtures && mkdir -p build/fixtures && python3 tests/make_headers_fixtures.py build/fixtures
```

```bash
build/hexray headers build/fixtures/valid-pe64.exe
```

```bash
build/hexray headers build/fixtures/pe-cut-in-imports
```

**Testa-te.**
- Porque é que o `reader_has()` usa `r->size - offset < length` e não `offset + length > r->size`?
- Porque é que o `reader_string()` precisa do `memchr`? O que aconteceria sem ele?
- Porque é que não se faz simplesmente um cast do ficheiro para uma `struct`?
- O que impede um ficheiro de declarar milhões de secções?

## 7. `scan`: procurar padrões conhecidos

**A ideia.** É um Ctrl+F para bytes. Um ficheiro de regras lista padrões em hexadecimal, em que `??` significa qualquer byte, e o hexray indica quais encontrou. Os wildcards são importantes porque as variantes de malware mudam pequenos detalhes à volta do mesmo código. As assinaturas de antivírus e o YARA partem desta ideia.

**O truque para ser rápido.** Testar todas as posições seria lento num ficheiro cheio do byte com que um padrão começa. Por isso, o `find_rule()` procura o byte do padrão que é *mais raro neste ficheiro*, com `memchr`, e só compara o padrão inteiro onde esse byte aparece.

**Lê em `scan.c`.** `parse_line()`, `parse_pattern()`, `find_rule()`, `matches_at()`.

**C que vais encontrar.** `getline`, cortar uma string no próprio sítio com `'\0'`, `int16_t` para guardar 257 valores diferentes, e `memchr`.

**Experimenta.**

```bash
build/hexray scan -r rules/starter.rules README.md
```

**Testa-te.**
- Porque é que um padrão não pode ser guardado num simples array de `unsigned char`?
- Porque é que `positions` é igual a `size - rule->length + 1`?
- Porque é que o `README.md` bate certo com regras de UPX? O que é que isso diz sobre as assinaturas?

## Como foi testado

| Técnica | O que prova | Onde |
|---|---|---|
| Comparar com uma ferramenta real | A saída do `dump` e do `hash` é idêntica à do `hexdump -C` e do `shasum` | `tests/test_dump.sh`, `tests/test_hash.sh` |
| Vetores de teste oficiais | O SHA-256 segue a norma | `tests/test_hash.sh` |
| Respostas conhecidas | Um ficheiro construído byte a byte tem um resultado que se pode calcular à mão | `tests/test_entropy.sh`, `tests/test_type.sh`, `tests/test_strings.sh`, `tests/test_scan.sh` |
| Ficheiros danificados, na build com sanitizers | Um ficheiro corrompido dá avisos e não um erro de memória | `tests/test_headers.sh` |

## O que fazer a seguir

Lê o código por esta ordem, do mais simples para o mais difícil: `dump.c`, `type.c`, `strscan.c`, `entropy.c`, `scan.c`, `sha256.c`, `binary.c`, `pe.c`.

Depois muda alguma coisa tu próprio. Dois bons primeiros projetos são assinalar extensões duplas como `invoice.pdf.exe` e reconhecer a forma curta `powershell -e`. Acrescenta um teste para cada um e corre o `make test`.

O hexray só sugere onde olhar. Uma etiqueta ou um match não prova que um ficheiro é malicioso, e um resultado limpo não prova que é seguro.
