"""
Struktura:
    App          - glavni prozor, prebacuje LoginFrame <-> MainFrame
    LoginFrame   - prva stranica: login / register
    MainFrame:
        PrivateKeyRingTab
        PublicKeyRingTab
        SignKeyTab
        SendMessageTab
        ReceiveMessageTab
"""

import os
import uuid
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

from cryptography.hazmat.primitives import serialization

from persistance.user import UserRing, UserService
from persistance.private_key_ring import PrivateKeyRing
from persistance.public_key_ring import PublicKeyRing
from services.pem_service import PEMService
from services.pgp_service import PgpService, PgpStep, ROOT_PATH, KEY_RING_DIRNAME
from pgp_messages import AlgorithmSymmetric, ROOT_PATH

KEY_RING_FOLDER = os.path.join(ROOT_PATH, KEY_RING_DIRNAME)


# ---------------------------------------------------------------------
# pomoćne funkcije
# ---------------------------------------------------------------------

def askPassword(parent, title="Šifra") -> bytes | None:
    value = simpledialog.askstring(title, "Unesite šifru:", show="*", parent=parent)
    if value is None or value == "":
        return None
    return value.encode("utf-8")


def formatTimestamp(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------
# glavni prozor
# ---------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mini PGP")
        self.geometry("900x600")

        # singletoni se inicijalizuju jednom, na startu aplikacije
        os.makedirs(ROOT_PATH, exist_ok=True)
        UserRing(ROOT_PATH)
        PrivateKeyRing(KEY_RING_FOLDER)
        PublicKeyRing(KEY_RING_FOLDER)

        self.currentFrame = None
        self.showLogin()

    def _swapFrame(self, frameClass, *args):
        if self.currentFrame is not None:
            self.currentFrame.destroy()
        self.currentFrame = frameClass(self, *args)
        self.currentFrame.pack(fill="both", expand=True)

    def showLogin(self):
        UserService().logout()
        self._swapFrame(LoginFrame)

    def showMain(self):
        self._swapFrame(MainFrame)


# ---------------------------------------------------------------------
# prva stranica: login / register
# ---------------------------------------------------------------------

class LoginFrame(ttk.Frame):
    def __init__(self, app: App):
        super().__init__(app, padding=40)
        self.app = app

        ttk.Label(self, text="Mini PGP", font=("TkDefaultFont", 18, "bold")).pack(pady=(0, 20))

        form = ttk.Frame(self)
        form.pack()

        ttk.Label(form, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.usernameEntry = ttk.Entry(form, width=30)
        self.usernameEntry.grid(row=0, column=1, pady=5)

        ttk.Label(form, text="Email:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.emailEntry = ttk.Entry(form, width=30)
        self.emailEntry.grid(row=1, column=1, pady=5)

        buttons = ttk.Frame(self)
        buttons.pack(pady=15)
        ttk.Button(buttons, text="Login", command=self.login).pack(side="left", padx=5)

    def _readForm(self) -> tuple[str, str] | None:
        username = self.usernameEntry.get().strip()
        email = self.emailEntry.get().strip()
        if not username or not email:
            messagebox.showerror("Greška", "Unesite i username i email.")
            return None
        return username, email

    def login(self):
        data = self._readForm()
        if data is None:
            return
        username, email = data
        user = UserService().login(username, email)
        if not user:
            messagebox.showerror("Greška", "Nesto je vec zauzeto tako da vas nemozemo ni logovati ni registrovati!.")
            return None

        self.app.showMain()




# ---------------------------------------------------------------------
# druga stranica: 4 taba
# ---------------------------------------------------------------------

class MainFrame(ttk.Frame):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app

        user = UserService().getActiveUser()
        self.pgpService = PgpService()

        header = ttk.Frame(self, padding=5)
        header.pack(fill="x")
        ttk.Label(header, text=f"Ulogovan: {user.username} <{user.email}>").pack(side="left")
        ttk.Button(header, text="Logout", command=self.app.showLogin).pack(side="right")

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.privateTab = PrivateKeyRingTab(notebook)
        self.publicTab = PublicKeyRingTab(notebook)
        self.signTab = SignKeyTab(notebook)
        self.sendTab = SendMessageTab(notebook, self.pgpService)
        self.receiveTab = ReceiveMessageTab(notebook, self.pgpService)

        notebook.add(self.privateTab, text="Private Key Ring")
        notebook.add(self.publicTab, text="Public Key Ring")
        notebook.add(self.signTab, text="Sign Key")
        notebook.add(self.sendTab, text="Send Message")
        notebook.add(self.receiveTab, text="Receive Message")

        # osveži sadržaj taba svaki put kad se pređe na njega
        notebook.bind("<<NotebookTabChanged>>",
                      lambda e: notebook.nametowidget(notebook.select()).refresh())


# ---------------------------------------------------------------------
# tab 1: Private Key Ring
# ---------------------------------------------------------------------

class PrivateKeyRingTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=10)

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=(0, 10))

        ttk.Label(toolbar, text="Veličina ključa:").pack(side="left")
        self.keySize = tk.IntVar(value=2048)
        ttk.Radiobutton(toolbar, text="1024", variable=self.keySize, value=1024).pack(side="left")
        ttk.Radiobutton(toolbar, text="2048", variable=self.keySize, value=2048).pack(side="left", padx=(0, 10))

        ttk.Button(toolbar, text="Generate", command=self.generate).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Import", command=self.importPair).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Export Public", command=self.exportPublic).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Export Pair", command=self.exportPair).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Delete Row", command=self.deleteRow).pack(side="left", padx=2)

        columns = ("keyId", "timestamp", "email")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        self.tree.heading("keyId", text="Key ID")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("email", text="Email")
        self.tree.pack(fill="both", expand=True)

        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for row in PrivateKeyRing(KEY_RING_FOLDER).getAllRows():
            self.tree.insert("", "end", iid=row.key_id.hex(),
                             values=(row.key_id.hex(), formatTimestamp(row.timestamp), row.user_email))

    def _selectedKeyId(self) -> bytes | None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Upozorenje", "Prvo selektujte red u tabeli.")
            return None
        return bytes.fromhex(selection[0])

    def generate(self):
        password = askPassword(self, "Šifra za novi ključ")
        if password is None:
            return
        try:
            PrivateKeyRing(KEY_RING_FOLDER).generateKeyPair(self.keySize.get(), password)
            self.refresh()
            messagebox.showinfo("Uspeh", "Ključ je generisan.")
        except Exception as error:
            messagebox.showerror("Greška", str(error))

    def importPair(self):
        path = filedialog.askopenfilename(title="Izaberite PEM fajl sa key pair-om",
                                          filetypes=[("PEM fajlovi", "*.pem"), ("Svi fajlovi", "*.*")])
        if not path:
            return
        password = askPassword(self, "Šifra za čuvanje privatnog ključa")
        if password is None:
            return
        try:
            PrivateKeyRing(KEY_RING_FOLDER).importKeyPair(path, password)
            self.refresh()
            messagebox.showinfo("Uspeh", "Key pair je uvezen.")
        except Exception as error:
            messagebox.showerror("Greška", str(error))

    def exportPublic(self):
        keyId = self._selectedKeyId()
        if keyId is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem",
                                            filetypes=[("PEM fajlovi", "*.pem")])
        if not path:
            return
        try:
            PrivateKeyRing(KEY_RING_FOLDER).exportPublicKey(keyId, path)
            messagebox.showinfo("Uspeh", "Javni ključ je izvezen.")
        except Exception as error:
            messagebox.showerror("Greška", str(error))

    def exportPair(self):
        keyId = self._selectedKeyId()
        if keyId is None:
            return
        password = askPassword(self, "Šifra privatnog ključa")
        if password is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem",
                                            filetypes=[("PEM fajlovi", "*.pem")])
        if not path:
            return
        try:
            PrivateKeyRing(KEY_RING_FOLDER).exportKeyPair(keyId, password, path)
            messagebox.showinfo("Uspeh", "Key pair je izvezen.")
        except Exception as error:
            messagebox.showerror("Greška", str(error))

    def deleteRow(self):
        keyId = self._selectedKeyId()
        if keyId is None:
            return
        if not messagebox.askyesno("Potvrda", "Obrisati ovaj ključ (i sve njegove unose u public ringu)?"):
            return
        try:
            PrivateKeyRing(KEY_RING_FOLDER).deleteRow(keyId)
            self.refresh()
        except Exception as error:
            messagebox.showerror("Greška", str(error))


# ---------------------------------------------------------------------
# tab 2: Public Key Ring
# ---------------------------------------------------------------------

class PublicKeyRingTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=10)

        # red 1: parametri za import
        importBar = ttk.Frame(self)
        importBar.pack(fill="x", pady=(0, 5))

        ttk.Label(importBar, text="Vlasnik ključa (email):").pack(side="left")
        self.ownerEmail = ttk.Combobox(importBar, width=25, state="readonly")
        self.ownerEmail.pack(side="left", padx=(2, 10))
        # Import dugme postaje aktivno tek kad se izabere vlasnik
        self.ownerEmail.bind("<<ComboboxSelected>>",
                             lambda e: self.importButton.configure(state="normal"))

        ttk.Label(importBar, text="Owner trust (0-100):").pack(side="left")
        self.ownerTrust = ttk.Spinbox(importBar, from_=0, to=100, width=5)
        self.ownerTrust.set(50)
        self.ownerTrust.pack(side="left", padx=(2, 10))

        self.importButton = ttk.Button(importBar, text="Import",
                                       command=self.importPublic, state="disabled")
        self.importButton.pack(side="left", padx=2)

        # red 2: akcije nad selektovanim redom
        actionBar = ttk.Frame(self)
        actionBar.pack(fill="x", pady=(0, 10))
        ttk.Button(actionBar, text="Export Public", command=self.exportPublic).pack(side="left", padx=2)
        ttk.Button(actionBar, text="Delete Row", command=self.deleteRow).pack(side="left", padx=2)

        columns = ("keyId", "timestamp", "owner", "addedBy", "trust", "legitimacy", "signatures")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        headings = {
            "keyId": "Key ID", "timestamp": "Timestamp", "owner": "Vlasnik",
            "addedBy": "Dodao", "trust": "Owner Trust", "legitimacy": "Legitimacy",
            "signatures": "Br. potpisa",
        }
        for col, text in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=110)
        self.tree.pack(fill="both", expand=True)

        self.refresh()

    def refresh(self):
        activeEmail = UserService().getActiveUser().email
        self.ownerEmail["values"] = [u.email for u in UserRing().users if u.email != activeEmail]
        self.importButton.configure(state="normal" if self.ownerEmail.get() else "disabled")

        self.tree.delete(*self.tree.get_children())
        for row in PublicKeyRing(KEY_RING_FOLDER).getAllRows():
            self.tree.insert("", "end", iid=row.key_id.hex(), values=(
                row.key_id.hex(), formatTimestamp(row.timestamp), row.owner_email,
                row.user_email, row.owner_trust, row.key_legitimacy, len(row.signatures),
            ))

    def _selectedKeyId(self) -> bytes | None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Upozorenje", "Prvo selektujte red u tabeli.")
            return None
        return bytes.fromhex(selection[0])

    def importPublic(self):
        ownerEmail = self.ownerEmail.get().strip()
        if not ownerEmail:
            messagebox.showerror("Greška", "Izaberite vlasnika ključa.")
            return
        path = filedialog.askopenfilename(title="Izaberite PEM fajl sa javnim ključem",
                                          filetypes=[("PEM fajlovi", "*.pem"), ("Svi fajlovi", "*.*")])
        if not path:
            return
        try:
            # veličina ključa se čita iz samog fajla, korisnik je ne bira
            _, publicPem = PEMService().importFromFile(path)
            keySize = serialization.load_pem_public_key(publicPem).key_size
            PublicKeyRing(KEY_RING_FOLDER).addRow(path, keySize,
                                                  ownerEmail, int(self.ownerTrust.get()))
            self.refresh()
            messagebox.showinfo("Uspeh", "Javni ključ je uvezen.")
        except Exception as error:
            messagebox.showerror("Greška", str(error))

    def exportPublic(self):
        keyId = self._selectedKeyId()
        if keyId is None:
            return
        row = PublicKeyRing(KEY_RING_FOLDER).getRowByKeyId(keyId)
        if row is None:
            messagebox.showerror("Greška", "Red nije pronađen.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem",
                                            filetypes=[("PEM fajlovi", "*.pem")])
        if not path:
            return
        try:
            PEMService().exportToFile(path, None, row.public_key_pem)
            messagebox.showinfo("Uspeh", "Javni ključ je izvezen.")
        except Exception as error:
            messagebox.showerror("Greška", str(error))

    def deleteRow(self):
        keyId = self._selectedKeyId()
        if keyId is None:
            return
        if not messagebox.askyesno("Potvrda", "Obrisati ovaj red?"):
            return
        try:
            PublicKeyRing(KEY_RING_FOLDER).deleteRow(keyId)
            self.refresh()
        except Exception as error:
            messagebox.showerror("Greška", str(error))


# ---------------------------------------------------------------------
# tab 3: Sign Key
# ---------------------------------------------------------------------

class SignKeyTab(ttk.Frame):
    """
    Potpisivanje javnih ključeva (web of trust).

    Prikazuju se SVI redovi iz PublicKeyRing-a (ne samo redovi aktivnog
    korisnika), jer signRow u core-u dozvoljava potpisivanje i tuđih redova.
    Red se može potpisati ako:
      - ga je dodao aktivni korisnik (svoj red), ili
      - je korisnik koji je dodao taj red prethodno dodao neki od AKTIVNIH
        korisnikovih ključeva u svoj deo public ringa (i tim ključem se potpisuje)
    -- ista pravila kao _canSign u core-u.
    """

    def __init__(self, parent):
        super().__init__(parent, padding=10)
        self.rowsByIid = {}          # iid u tabeli -> PublicKeyRingRow
        self.signerChoices = {}      # hex keyId -> bytes keyId

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=(0, 10))

        ttk.Label(toolbar, text="Filter:").pack(side="left")
        self.filterVar = tk.StringVar(value="sve")
        for text, value in (("Svi", "sve"), ("Nepotpisani", "nepotpisani"), ("Potpisani", "potpisani")):
            ttk.Radiobutton(toolbar, text=text, variable=self.filterVar,
                            value=value, command=self.refresh).pack(side="left", padx=3)

        ttk.Label(toolbar, text="Ključ za potpis:").pack(side="left", padx=(20, 2))
        self.signerCombo = ttk.Combobox(toolbar, state="readonly", width=22)
        self.signerCombo.pack(side="left")

        self.signButton = ttk.Button(toolbar, text="Potpiši", command=self.sign, state="disabled")
        self.signButton.pack(side="left", padx=5)

        columns = ("keyId", "owner", "addedBy", "signedByMe", "canSign")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        headings = {
            "keyId": "Key ID", "owner": "Vlasnik ključa", "addedBy": "Dodao u ring",
            "signedByMe": "Potpisao sam", "canSign": "Mogu da potpišem",
        }
        for col, text in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=140)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.onSelect)

        self.refresh()

    # ------------------------------------------------------------- helpers

    def _myKeyIds(self) -> set[bytes]:
        return {row.key_id for row in PrivateKeyRing(KEY_RING_FOLDER).getAllRows()}

    def _signedByMe(self, row) -> bool:
        myKeys = self._myKeyIds()
        return any(sig.idpu_signature in myKeys for sig in row.signatures)

    def _validSignerKeys(self, row) -> list[bytes]:
        """Moji ključevi kojima je dozvoljeno potpisati ovaj red (pravila iz
        _canSign), bez onih koji su taj red već potpisali."""
        activeEmail = UserService().getActiveUser().email
        myKeys = self._myKeyIds()
        allRows = PublicKeyRing(KEY_RING_FOLDER).rows

        if row.user_email == activeEmail:
            candidates = list(myKeys)
        else:
            # ključevi koje je vlasnik reda (row.user_email) dodao u svoj deo
            # ringa, a pripadaju meni
            candidates = [
                other.key_id for other in allRows
                if other.user_email == row.user_email
                and other.owner_email == activeEmail
                and other.key_id in myKeys
            ]

        alreadySigned = {sig.idpu_signature for sig in row.signatures}
        return [keyId for keyId in candidates if keyId not in alreadySigned]

    # ------------------------------------------------------------- UI logika

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        self.rowsByIid = {}
        self.signerCombo.set("")
        self.signerCombo["values"] = []
        self.signButton.configure(state="disabled")

        selectedFilter = self.filterVar.get()
        for row in PublicKeyRing(KEY_RING_FOLDER).rows:
            signedByMe = self._signedByMe(row)
            if selectedFilter == "nepotpisani" and signedByMe:
                continue
            if selectedFilter == "potpisani" and not signedByMe:
                continue

            canSign = len(self._validSignerKeys(row)) > 0
            # isti keyId moze postojati u vise redova (razliciti user_email),
            # pa iid mora biti kombinacija
            iid = f"{row.key_id.hex()}|{row.user_email}"
            self.rowsByIid[iid] = row
            self.tree.insert("", "end", iid=iid, values=(
                row.key_id.hex(), row.owner_email, row.user_email,
                "Da" if signedByMe else "Ne",
                "Da" if canSign else "Ne",
            ))

    def onSelect(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        row = self.rowsByIid[selection[0]]

        validKeys = self._validSignerKeys(row)
        self.signerChoices = {keyId.hex(): keyId for keyId in validKeys}
        self.signerCombo["values"] = list(self.signerChoices.keys())
        if validKeys:
            self.signerCombo.current(0)
            self.signButton.configure(state="normal")
        else:
            self.signerCombo.set("")
            self.signButton.configure(state="disabled")

    def sign(self):
        selection = self.tree.selection()
        if not selection:
            return
        row = self.rowsByIid[selection[0]]

        signerHex = self.signerCombo.get()
        if not signerHex:
            return
        signerKeyId = self.signerChoices[signerHex]

        password = askPassword(self, "Šifra ključa za potpis")
        if password is None:
            return

        try:
            PublicKeyRing(KEY_RING_FOLDER).signRow(row.user_email, row.key_id, signerKeyId, password)
            self.refresh()
            messagebox.showinfo("Uspeh", "Ključ je potpisan.")
        except Exception as error:
            messagebox.showerror("Greška", str(error))


# ---------------------------------------------------------------------
# tab 3: Send Message
# ---------------------------------------------------------------------

class SendMessageTab(ttk.Frame):
    def __init__(self, parent, pgpService: PgpService):
        super().__init__(parent, padding=10)
        self.pgpService = pgpService
        self.keyChoices: dict[str, bytes] = {}   # label -> keyId

        # checkboxovi za opcione PGP servise
        options = ttk.LabelFrame(self, text="PGP servisi", padding=5)
        options.pack(fill="x", pady=(0, 5))

        self.useAuth = tk.BooleanVar()
        self.useEncryption = tk.BooleanVar()
        self.useCompression = tk.BooleanVar()
        self.useRadix = tk.BooleanVar()
        ttk.Checkbutton(options, text="Authentication (potpis)", variable=self.useAuth,
                        command=self.refreshKeyChoices).pack(side="left", padx=5)
        ttk.Checkbutton(options, text="Encryption", variable=self.useEncryption,
                        command=self.refreshKeyChoices).pack(side="left", padx=5)
        ttk.Checkbutton(options, text="Compression", variable=self.useCompression).pack(side="left", padx=5)
        ttk.Checkbutton(options, text="Radix-64", variable=self.useRadix).pack(side="left", padx=5)

        # primalac + ključevi + algoritam
        params = ttk.Frame(self)
        params.pack(fill="x", pady=5)

        ttk.Label(params, text="Primalac:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        self.recipientCombo = ttk.Combobox(params, state="readonly", width=30)
        self.recipientCombo.grid(row=0, column=1, sticky="w", pady=2)
        self.recipientCombo.bind("<<ComboboxSelected>>", lambda e: self.refreshKeyChoices())

        ttk.Label(params, text="Ključ primaoca (za encryption):").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        self.recipientKeyCombo = ttk.Combobox(params, state="readonly", width=30)
        self.recipientKeyCombo.grid(row=1, column=1, sticky="w", pady=2)

        ttk.Label(params, text="Vaš ključ (za potpis):").grid(row=2, column=0, sticky="e", padx=5, pady=2)
        self.signerKeyCombo = ttk.Combobox(params, state="readonly", width=30)
        self.signerKeyCombo.grid(row=2, column=1, sticky="w", pady=2)

        ttk.Label(params, text="Algoritam:").grid(row=3, column=0, sticky="e", padx=5, pady=2)
        self.algorithmCombo = ttk.Combobox(params, state="readonly", width=30,
                                           values=[a.value for a in AlgorithmSymmetric])
        self.algorithmCombo.current(0)
        self.algorithmCombo.grid(row=3, column=1, sticky="w", pady=2)

        ttk.Label(params, text="Naziv fajla:").grid(row=4, column=0, sticky="e", padx=5, pady=2)
        self.filenameEntry = ttk.Entry(params, width=32)
        self.filenameEntry.grid(row=4, column=1, sticky="w", pady=2)
        ttk.Label(params, text="(dodaje se _guid.pgp)").grid(row=4, column=2, sticky="w", padx=5)

        # poruka
        ttk.Label(self, text="Poruka:").pack(anchor="w")
        self.messageText = tk.Text(self, height=10)
        self.messageText.pack(fill="both", expand=True, pady=(0, 5))

        ttk.Button(self, text="Send", command=self.send).pack()

        self.refresh()

    def refresh(self):
        activeEmail = UserService().getActiveUser().email
        self.recipientCombo["values"] = [u.email for u in UserRing().users]
        self.refreshKeyChoices()

        # sopstveni ključevi za potpis
        ownKeys = PrivateKeyRing(KEY_RING_FOLDER).getAllRows()
        self.signerKeyCombo["values"] = [row.key_id.hex() for row in ownKeys]
        if ownKeys:
            self.signerKeyCombo.current(0)

    def refreshKeyChoices(self):
        """Ključevi kojima se može šifrovati za izabranog primaoca: njegovi
        ključevi iz public ringa + sopstveni ključevi ako šaljemo sebi."""
        recipient = self.recipientCombo.get()
        activeEmail = UserService().getActiveUser().email
        self.keyChoices = {}

        for row in PublicKeyRing(KEY_RING_FOLDER).getAllRows():
            if row.owner_email == recipient:
                self.keyChoices[f"{row.key_id.hex()} (public ring)"] = row.key_id

        if recipient == activeEmail:
            for row in PrivateKeyRing(KEY_RING_FOLDER).getAllRows():
                self.keyChoices[f"{row.key_id.hex()} (moj ključ)"] = row.key_id

        self.recipientKeyCombo["values"] = list(self.keyChoices.keys())
        if self.keyChoices:
            self.recipientKeyCombo.current(0)
        else:
            self.recipientKeyCombo.set("")

    def send(self):
        recipientEmail = self.recipientCombo.get()
        if not recipientEmail:
            messagebox.showerror("Greška", "Izaberite primaoca.")
            return
        recipient = UserRing().findByEmail(recipientEmail)

        message = self.messageText.get("1.0", "end-1c")
        if not message:
            messagebox.showerror("Greška", "Unesite poruku.")
            return

        steps = PgpStep.NONE
        if self.useAuth.get():
            steps |= PgpStep.AUTHENTICATION
        if self.useCompression.get():
            steps |= PgpStep.COMPRESSION
        if self.useEncryption.get():
            steps |= PgpStep.ENCRYPTION
        if self.useRadix.get():
            steps |= PgpStep.CONVERSION

        signerKeyId = None
        signerPassword = None
        if self.useAuth.get():
            if not self.signerKeyCombo.get():
                messagebox.showerror("Greška", "Za potpis izaberite svoj ključ.")
                return
            signerKeyId = bytes.fromhex(self.signerKeyCombo.get())
            signerPassword = askPassword(self, "Šifra vašeg privatnog ključa")
            if signerPassword is None:
                return

        recipientKeyId = None
        if self.useEncryption.get():
            label = self.recipientKeyCombo.get()
            if not label:
                messagebox.showerror("Greška", "Za encryption izaberite ključ primaoca "
                                               "(uvezite ga prvo u Public Key Ring).")
                return
            recipientKeyId = self.keyChoices[label]

        algorithm = next(a for a in AlgorithmSymmetric if a.value == self.algorithmCombo.get())

        # naziv fajla: korisnikov unos + _guid, da ne bude istoimenih fajlova
        baseName = os.path.splitext(self.filenameEntry.get().strip())[0] or "msg"
        filename = f"{baseName}_{uuid.uuid4().hex[:8]}.pgp"
        outputPath = os.path.join(recipient.message_box_folder_path, filename)
        os.makedirs(recipient.message_box_folder_path, exist_ok=True)

        try:
            self.pgpService.send(
                message, outputPath,
                filename=filename,
                steps=steps,
                signer_key_id=signerKeyId,
                signer_password=signerPassword,
                recipient_key_id=recipientKeyId,
                algorithm=algorithm,
            )
            messagebox.showinfo("Uspeh", f"Poruka je poslata u sanduče korisnika {recipientEmail}.")
            self.messageText.delete("1.0", "end")
        except Exception as error:
            messagebox.showerror("Greška", str(error))


# ---------------------------------------------------------------------
# tab 4: Receive Message
# ---------------------------------------------------------------------

class ReceiveMessageTab(ttk.Frame):
    def __init__(self, parent, pgpService: PgpService):
        super().__init__(parent, padding=10)
        self.pgpService = pgpService
        self.folder = UserService().getActiveUser().message_box_folder_path

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=(0, 10))

        ttk.Label(toolbar, text="Filter:").pack(side="left")
        self.filterVar = tk.StringVar(value="sve")
        for text, value in (("Sve", "sve"), ("Primljene (.pgp)", ".pgp"), ("Sačuvane (.txt)", ".txt")):
            ttk.Radiobutton(toolbar, text=text, variable=self.filterVar,
                            value=value, command=self.refresh).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Osveži", command=self.refresh).pack(side="right")

        self.tree = ttk.Treeview(self, columns=("file",), show="headings")
        self.tree.heading("file", text="Fajl (dvoklik za otvaranje)")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self.openSelected)

        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        selectedFilter = self.filterVar.get()
        path = os.path.join(ROOT_PATH, self.folder)
        for name in sorted(os.listdir(path)):
            if selectedFilter != "sve" and not name.endswith(selectedFilter):
                continue
            self.tree.insert("", "end", iid=name, values=(name,))

    def openSelected(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        name = selection[0]
        path = os.path.join(self.folder, name)

        if name.endswith(".txt"):
            with open(path, "r", encoding="utf-8") as file:
                content = file.read()
            self._showTextWindow(name, content)
            return

        # .pgp: probaj bez šifre; ako je šifrovana, core traži šifru pa je pitamo
        try:
            result = self.pgpService.receive(path)
        except ValueError as error:
            if "password is required" not in str(error):
                messagebox.showerror("Greška", str(error))
                return
            password = askPassword(self, "Šifra vašeg privatnog ključa")
            if password is None:
                return
            try:
                result = self.pgpService.receive(path, password=password)
            except Exception as innerError:
                messagebox.showerror("Greška", str(innerError))
                return
        except Exception as error:
            messagebox.showerror("Greška", str(error))
            return

        ReceivedMessageWindow(self, result, self.folder, name)

    def _showTextWindow(self, title, content):
        window = tk.Toplevel(self)
        window.title(title)
        text = tk.Text(window, width=80, height=25)
        text.insert("1.0", content)
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)


class ReceivedMessageWindow(tk.Toplevel):
    """Prikaz svih podataka iz ReceiveResult + čuvanje originala u .txt."""

    def __init__(self, parent, result, folder: str, sourceName: str):
        super().__init__(parent)
        self.title(f"Primljena poruka: {sourceName}")
        self.result = result
        self.folder = folder
        self.sourceName = sourceName

        info = ttk.Frame(self, padding=10)
        info.pack(fill="x")

        appliedNames = [step.name for step in PgpStep
                        if step not in (PgpStep.NONE, PgpStep.ALL) and step in result.applied_steps]
        rows = [
            ("Timestamp poruke:", formatTimestamp(result.message.timestamp)),
            ("Filename:", result.message.filename or "-"),
            ("Primenjeni koraci:", ", ".join(appliedNames) or "nijedan"),
        ]
        if result.signature_valid is None:
            rows.append(("Potpis:", "poruka nije potpisana"))
        else:
            status = "VALIDAN" if result.signature_valid else "NEVALIDAN"
            rows.append(("Potpis:", status))
            rows.append(("Potpisao (keyId):", result.signer_key_id.hex() if result.signer_key_id else "-"))
            rows.append(("Potpisao (email):", result.signer_email or "nepoznat"))

        for i, (label, value) in enumerate(rows):
            ttk.Label(info, text=label, font=("TkDefaultFont", 9, "bold")).grid(row=i, column=0, sticky="e", padx=5)
            ttk.Label(info, text=value).grid(row=i, column=1, sticky="w")

        ttk.Label(self, text="Poruka:", padding=(10, 0)).pack(anchor="w")
        text = tk.Text(self, width=80, height=15)
        text.insert("1.0", result.message.msg)
        text.configure(state="disabled")
        text.pack(fill="both", expand=True, padx=10)

        ttk.Button(self, text="Sačuvaj original (.txt)", command=self.saveOriginal).pack(pady=10)

    def saveOriginal(self):
        defaultName = os.path.splitext(self.sourceName)[0] + ".txt"
        path = filedialog.asksaveasfilename(initialdir=self.folder, initialfile=defaultName,
                                            defaultextension=".txt",
                                            filetypes=[("Tekst fajlovi", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as file:
            file.write(self.result.message.msg)
        messagebox.showinfo("Uspeh", "Originalna poruka je sačuvana.")


if __name__ == "__main__":
    App().mainloop()