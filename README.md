# Mehanizmi zaštite privatnosti u EUDI novčanicima - završni rad

## O projektu

Ovaj rad istražuje i implementira mehanizme zaštite privatnosti unutar EUDI (European Digital Identity) Wallet arhitekture.

Fokus rada je na demonstraciji mehanizama koji osiguravaju privatnost korisnika u digitalnom ekosustavu, prvenstveno kroz:
 - Selektivno otkrivanje informacija (Selective Disclosure): Omogućuje korisniku da prilikom dokazivanja identiteta otkrije samo specifične atribute (npr. samo ime ili godinu rođenja) bez otkrivanja cijelog sadržaja digitalne vjerodajnice.
 - nepovezivost (Unlinkability): Analiza i implementacija pristupa koji sprječavaju treće strane da povežu različite prezentacije istog korisnika, čime se štiti digitalni trag pojedinca.

## Arhitektura sustava
Prototip se temelji na trostranom modelu povjerenja:

 - Izdavatelj (Issuer): Kreira vjerodajnicu koristeći mehanizme za selektivno otkrivanje.

 - Korisnik (Holder): Upravlja vjerodajnicama u novčaniku i vrši selektivnu objavu podataka prema zahtjevu.

 - Provjeritelj (Verifier): Kriptografski verificira autentičnost i integritet prezentiranih podataka.

## Ključne funkcionalnosti sustava
Sustav implementira napredne mehanizme zaštite privatnosti i integriteta podataka kroz sljedeće funkcionalnosti:

Batch izdavanje vjerodajnica (Mass Issuance): Podrška za izdavanje skupa tokena (vjerodajnica) u jednom koraku, pri čemu je svaki token vezan uz jedinstveni kriptografski ključ korisnika (Holder key), čime se osigurava visoka razina skalabilnosti.

Rotacija tokena i sprječavanje povezivosti (Unlinkability): Implementiran je sustav spremnika tokena (Token Pool) koji omogućuje korisniku da za svaku prezentaciju koristi novi, neovisni token, čime se onemogućuje verifikatorima praćenje i profiliranje korisnika kroz različite interakcije.

Kriptografsko povezivanje ključa (Key Binding): Osigurana je autentičnost prezentacije putem cnf (Confirmation) zahtjeva unutar SD-JWT-a. Korištenjem jwk (JSON Web Key), te parametara nonce i aud (Audience), sustav sprječava napade ponavljanjem (Replay attacks) i osigurava da vjerodajnicu može prezentirati samo legitimni vlasnik ključa.

Izvanmrežna verifikacija (Offline Verification): Dizajn sustava omogućuje verifikatoru potpunu provjeru vjerodostojnosti i integriteta podataka bez potrebe za sinkronom komunikacijom s izdavačem (Issuer), što povećava brzinu odziva i štiti privatnost korisnika (izdavač ne zna kada i gdje se vjerodajnica koristi).

Sigurnost transportnog sloja: Sva komunikacija između sudionika (Issuer, Holder, Verifier) odvija se isključivo putem zaštićenog HTTPS protokola uz obaveznu mTLS (mutual TLS) autentifikaciju, osiguravajući povjerljivost i integritet kanala.

Upravljanje stanjem izazova (Challenge Management): Implementiran je mehanizam za upravljanje životnim vijekom nonce parametara (TTL - Time to Live) uz automatski proces čišćenja (Cleanup) isteklih izazova, čime se optimiziraju resursi i jača sigurnost sustava protiv zastarjelih zahtjeva.

## Pokretanje

Na početku je potrebno postaviti virtualno okruženje (u svakom terminalu koji se koristi):
```bash
python -m venv venv
source venv/Scripts/activate
pip install -r requirements.txt
```

Zatim se u zasebnim terminalima pokreću redom:

```bash
python issuer.py
```

```bash
python verifier.py
```

```bash
python holder.py
```

## Dataset za test ulaze

Sustav može koristiti dataset korisnika iz datoteke `data/users.json`.

- issuer pri pokretanju učitava korisnike iz `data/users.json`
- ako datoteka ne postoji, koristi korisnike u kodu

Sustav također podržava scenarije testiranja iz `data/test_cases.json`.

- holder pri pokretanju prvo pokušava učitati `data/test_cases.json`
- ako datoteka postoji, automatski izvršava sve test caseove iz nje
- ako datoteka ne postoji, pokreće default demo scenarij


## Unlinkability

U ovom projektu unlinkability promatram na praktičnoj razini, kao sposobnost sustava da smanji mogućnost povezivanja više radnji istog korisnika.

### Presentation unlinkability

Znači da isti verifier ne može lako prepoznati da dvije prezentacije dolaze od istog korisnika.

U ovom sustavu to se postiže ovako:

- za svaku prezentaciju koristi se novi token
- za svaki token koristi se novi holder key pair
- svaki proof je vezan uz konkretan `nonce` i `aud` verifiera

Zbog toga se isti credential ne koristi više puta.

U holderu se zato po prezentaciji ispisuju `token_fp` i `key_fp`, zajedno s oznakom `new = True/False`, kako bi se odmah vidjelo jesu li token i holder key novi u odnosu na prethodnu prezentaciju.

### Verifier-verifier unlinkability

Znači da dva različita verifiera ne bi trebala jednostavno povezati dvije prezentacije kao radnje istog korisnika.

Postignuto na način:

- za svaku prezentaciju se koristi novi token
- svaki verifier ima vlastiti challenge
- svaki verifier vidi samo minimalni skup claimova koji mu treba

Ipak, ovo nije potpuna kriptografska unlinkability, jer se prezentacije i dalje mogu usporediti po otkrivenim claimovima ili metapodacima ako ih verifieri međusobno dijele.

### Issuer-verifier unlinkability

Znači da issuer ne zna kada i gdje se neki token koristi.

U ovom projektu to se postiže tako da verifier ne zove issuer tijekom svake verifikacije, nego koristi lokalno spremljeni issuer public key za offline provjeru potpisa.

Zbog toga issuer nije online uključen u svaki verify dogadaj i ne dobiva izravan signal o svakom korištenju tokena.


## Ograničenja sustava i preostali rizici
Iako sustav značajno unapređuje privatnost korisnika, implementirani model ima određena ograničenja koja su rezultat balansa između sigurnosti, privatnosti i praktične primjenjivosti:

Praktična nasuprot kriptografske nepovezivosti: Sustav ne koristi napredne kriptografske primitive za postizanje potpune matematičke nepovezivosti. Umjesto toga, primjenjuje se praktična nepovezivost (Practical Unlinkability) kroz intenzivnu rotaciju jednokratnih tokena i pripadajućih ključeva, što značajno otežava korelaciju, ali je teoretski ne eliminira u potpunosti.

Curenje informacija putem metapodataka: Mehanizmi zaštite na aplikacijskom sloju (SD-JWT) ne maskiraju u potpunosti metapodatke i obrasce mrežnog prometa. Napredni napadač s uvidom u mrežnu infrastrukturu mogao bi kroz analizu veličine paketa, vremena slanja i IP adresa pokušati korelirati različite prezentacije istog korisnika.

Signalizacija putem mTLS identiteta: Korištenje mTLS-a (mutual TLS) osigurava kanal, ali klijentski certifikati koji se koriste za autentifikaciju pri uspostavi sesije mogu poslužiti kao stalni identifikatori. Ako se isti mTLS certifikat koristi kroz više sesija prema različitim verifikatorima, on postaje signal za povezivanje korisničkih aktivnosti usprkos rotaciji samih tokena.


