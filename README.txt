Captured flag 1: flag{s1mUl4teD_BOF_in_PyTH0n}
Captured flag 2: flag{6ae29f75814549cc9094b8c11dbe22ee}
Captured flag 3: flag{7h4t_K3y_wAsNT_r34l1y_rAnd0M}

1. Pierwsza flaga: jest błąd w handlerze podmieniania klucza - można wysłać coś krótszego niż 16 bajtów,
wtedy pierwsze n bajtów zostanie podmienione, a reszta pozostanie z oryginalnego klucza. Można tego wykorzystać aby
w maksymalnie 255 próbach odgadnąć ostatni bajt klucza szyfrowania, potem przedostatni itp., wydobyć cały klucz szyfrowania
i odszyfrować ciphertext z flagą.

2. Kluczem logowania użytkownika jest jego username zaszyfrowane kluczem publicznym RSA - znamy username (flag), wyciągamy
klucz publiczny, szyfrujemy nim username, wysyłamy do login i mamy flagę.

3. Atak statystyczny - urandom(1) daje rzeczywiście bezpieczny keystream, ale robienie na nim modulo to psuje, bo len(charset)
nie jest dzielnikiem max wartości i przez to dla każdego bajtu plaintextu jesteśmy w stanie wyliczyć z jakim prawdopodobieństwem
po zaszyfrowaniu będzie równy E. Nie dla każdego E to prawdopodobieństwo jest równe. Wiedząc to jesteśmy w stanie spróbkować
wielokrotnie zaszyfrowany tekst z serwera, policzyć jaki znak występuje najrzadziej na n-tej pozycji zaszyfrowanego tekstu
i dzięki temu zgadnąć jaki znak plaintextu się pod nim kryje.
