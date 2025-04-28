# Ethernet-Switch-with-VLAN-and-STP

Procesul de comutare (30p):

Pentru prima cerinta, am folosit pseudocodul ofeirt in enunt. In plus, am creat un dictionar Mac_table,
ce are drept cheie o adresa MAC si, ca valoare, interfata pe care se gaseste adresa.
De asemenea, am creat functia is_unicast, care verifica daca cel mai putin semnificativ bit din primul byte
este 0, caz in care adresa este unicast.

VLAN (30p):

Pentru a doua cerinta, am adus modificari in implementarea procesului de comutare si am creat functii separate:
Pentru a citi configurarea switch-ului, am creat functia parse_vlan_from_config, care citeste, de pe prima linie,
prioritatea switchului curent, dupa care preia o pereche de valori pentru urmatoarele linii. Daca a doua valoare
este 'T', avem un port trunk, si ii salvez id-ul vlan-ului ca '-2' intr-un dictionar nume_interfata - vlan_id, numit
vlan_config. In caz contrar, a doua valoare este id-ul vlan-ului si il salvez in format int.
In main, am prealuat vlan_config si switch_priority folosind functia creata. In cadrul while-ului, pentru interfata
curenta pe care a sosit pachetul, setez vlan_id-ul de provenienta ca cel al sursei prin vlan_config, deoarece exista
posibilitatea ca pachetul ajuns sa nu contina vlan_id setat.
La trimiterea pachetului am tratat 4 cazuri in functie de provenienta si destinatia pachetului (destinatia preluata 
din vlan_config). Totusi, am intalnit o problema: nu am mai putut verifica provenienta dupa vlan_id din moment ce
l-am modificat, asa ca am facut functia has_vlan_tag, ce verifica in componenta pachetului 'data' daca exista 
vlan_id-ul setat. In continuare, in functie de caz, sterge sau adauga tag-ul si trimite pachetul.

STP (40p):

Pentru a treia cerinta, am creat 5 variabile globale, deoarece fiecare este atribuita mereu switch-ului curent
(4 valori si un dictionar interfaces_states ce retine starea interfetelor).
Pentru initializarea STP am creat o functie separata ce seteaza valorile globale conform pseudocodului.
Pentru trimiterea pachetului la fiecare secunda am avut nevoie de o functie ce creeaza un pachet BPDU conform
screenshot-ului de pe OCW din Wireshark. Am creat fiecare camp prin struct.pack si am concatenat totul la final.
In continuare, am urmarit pseudocodul si am trimis frame-ul format prin make_bpdu cu valorile corespunzatoare.
Am creat functia de gestionare a pachetului BDPU conform pseudocodului, dar, am folosit doar starile 'BLOCKING' si
'DESIGNATED_PORT', fara 'LISTENING', deoarece nu modifica implementarea. De asemenea, verificarea daca am fost
root bridge se face in functie de valorile globale, asa ca le-am modificat dupa verificare, fata de pseudocod, care
le modifica inainte.
In main, dupa initializarea STP si crearea thread-ului pentru trimiterea pachetelor BPDU, daca destinatia adresei
MAC a pachetului primit este cea de multicast, am primit un pachet BPDU din care parsez datele cu o functie separata
(configuratia BPDU incepe de la bitul 22 din pachetul primit).
Cu aceste date apelez functia de gestionare a pachetului BPDU. In plus, la trimiterea pachetului, am adaugat o
conditie, anume ca porturile destinatie sa nu fie in starea 'BLOCKING'.
