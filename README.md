# Zavrsni-rad

SD-JWT demo s tri uloge:

- issuer izdaje SD-JWT
- holder stvara prezentacije
- verifier provjerava prezentacije

## Funkcionalnosti

- issuer moze izdati vise tokena odjednom, svaki vezan uz zaseban holder key
- holder koristi token pool i za svaku prezentaciju uzima novi token
- uveden je key binding preko `cnf.jwk`, `nonce` i `aud`
- verifier radi bez online poziva issueru tijekom verifikacije
- komunikacija ide preko HTTPS uz mTLS
- dodan je TTL za nonce i cleanup isteklih challengea

## Pokretanje

Redom:

```bash
python issuer.py
```

```bash
python verifier.py
```

```bash
python holder.py
```


## Unlinkability

U ovom projektu unlinkability promatram na prakticnoj razini, kao sposobnost sustava da smanji mogucnost povezivanja vise radnji istog korisnika.

### Presentation unlinkability

Znaci da isti verifier ne moze lako prepoznati da dvije prezentacije dolaze od istog korisnika.

U ovom sustavu to se postize ovako:

- za svaku prezentaciju koristi se novi token
- za svaki token koristi se novi holder key pair
- svaki proof je vezan uz konkretan `nonce` i `aud` verifiera

Zbog toga se isti credential ne koristi vise puta.

U holderu se zato po prezentaciji ispisuju `token_fp` i `key_fp`, zajedno s oznakom `new = True/False`, kako bi se odmah vidjelo jesu li token i holder key novi u odnosu na prethodnu prezentaciju.

### Verifier-verifier unlinkability

Znaci da dva razlicita verifiera ne bi trebala jednostavno povezati dvije prezentacije kao radnje istog korisnika.

Postignuto na nacin:

- za svaku prezentaciju se koristi novi token
- svaki verifier ima vlastiti challenge
- svaki verifier vidi samo minimalni skup claimova koji mu treba

Ipak, ovo nije potpuna kriptografska unlinkability, jer se prezentacije i dalje mogu usporediti po otkrivenim claimovima ili metapodacima ako ih verifieri medusobno dijele.

### Issuer-verifier unlinkability

Znaci da issuer ne zna kada i gdje se neki token koristi.

U ovom projektu to postize tako da verifier ne zove issuer tijekom svake verifikacije, nego koristi lokalno spremljeni issuer public key za offline provjeru potpisa.

Zbog toga issuer nije online ukljucen u svaki verify dogadaj i ne dobiva izravan signal o svakom koristenju tokena.



## Ogranicenja

- nije potpuna kriptografska unlinkability, nego practical unlinkability kroz rotaciju tokena i kljuceva
- metapodaci i mrezni promet i dalje mogu otkriti korelaciju
- mTLS identitet i dalje moze biti signal za povezivanje sesija


