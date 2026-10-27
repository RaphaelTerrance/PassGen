"""
PassGen - Modern Graphical User Interface (Windows / CustomTkinter)
Theme Palette:
  Dark Background:        #15171a
  Card Background:        #1e2126
  Entry / Input Background:#24282e
  Accent Orange/Red:      #f14e32
  Accent Hover:           #d43d22
  Primary Text:           #ffffff
  Outer Wheel Grey:       #343a40
  Inner Wheel Grey:       #2a2e33
  Wheel Lettering Grey:   #adb5bd
  Border Grey:            #373e47

Features:
  - Authentication Gateway (Demo Mode, User Login, New User Registration)
  - 1. See the Vault (Encrypted Records with per-item Decryption)
  - 2. Add New Password:
      - 5 Cipher Methods from PassGen v2:
        - Caesar Shift (Shift N)
        - ROT13 (Shift 13)
        - Vigenère Cipher (Keyword)
        - XOR Stream Cipher (Hex Stream)
        - AES-128 CBC (16-Byte Key)
      * Real-time Regex Password Strength Meter (Length, Case, Numbers, Symbols)
      * Live Ciphertext Preview
      * Interactive Cipher Dial Visualizer with Canvas
  - 3. Export Saved Passwords (Password Verification Gated + Decrypted CSV/Text Export)
"""

import math
import os
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
from PIL import Image

import engine

# Strict Color Palette
BG_DARK = "#15171a"
CARD_BG = "#1e2126"
ENTRY_BG = "#24282e"
ACCENT_ORANGE = "#f14e32"
ACCENT_HOVER = "#d43d22"
TEXT_PRIMARY = "#ffffff"
TEXT_MUTED = "#868e96"
OUTER_WHEEL_GREY = "#343a40"
INNER_WHEEL_GREY = "#2a2e33"
WHEEL_LETTERING_GREY = "#adb5bd"
BORDER_GREY = "#373e47"

CIPHER_CHOICES = [
    "Caesar (Shift N)",
    "ROT13 (Shift 13)",
    "Vigenère (Keyword)",
    "XOR Stream (Key)",
    "AES-128 (16-Byte Key)"
]


class CipherDialCanvas(ctk.CTkCanvas):
    """
    Renders an interactive cipher dial visualizer:
    Outer ring: Plaintext alphabet (Outer Wheel Grey #343a40)
    Inner ring: Shifted cipher alphabet (Inner Wheel Grey #2a2e33)
    Lettering: Grey #adb5bd
    Indicator & Active shifted letter: Accent Orange/Red #f14e32
    """
    def __init__(self, master, current_shift: int = 3, **kwargs):
        super().__init__(
            master,
            width=kwargs.get("width", 260),
            height=kwargs.get("height", 260),
            bg=CARD_BG,
            highlightthickness=0,
            **{k: v for k, v in kwargs.items() if k not in ("width", "height")}
        )
        self.shift = current_shift % 26
        self.bind("<Configure>", lambda e: self.draw_dial())
        self.draw_dial()

    def set_shift(self, shift: int):
        self.shift = shift % 26
        self.draw_dial()

    def draw_dial(self):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 10 or h < 10:
            w = 260
            h = 260

        cx = w / 2
        cy = h / 2
        r_outer = min(cx, cy) - 10
        r_inner = r_outer * 0.68
        r_center = r_outer * 0.38

        if r_outer <= 20:
            return

        # 1. Outer Wheel Circle
        self.create_oval(
            cx - r_outer, cy - r_outer,
            cx + r_outer, cy + r_outer,
            fill=OUTER_WHEEL_GREY, outline=BORDER_GREY, width=2
        )

        # 2. Inner Wheel Circle
        self.create_oval(
            cx - r_inner, cy - r_inner,
            cx + r_inner, cy + r_inner,
            fill=INNER_WHEEL_GREY, outline=BORDER_GREY, width=2
        )

        # 3. Center Hub
        self.create_oval(
            cx - r_center, cy - r_center,
            cx + r_center, cy + r_center,
            fill=BG_DARK, outline=ACCENT_ORANGE, width=2
        )

        # Shift Badge in center hub
        self.create_text(
            cx, cy - 8,
            text=f"+{self.shift}",
            fill=ACCENT_ORANGE,
            font=("Helvetica", max(13, int(r_center * 0.38)), "bold")
        )
        self.create_text(
            cx, cy + 12,
            text="SHIFT",
            fill=WHEEL_LETTERING_GREY,
            font=("Helvetica", max(8, int(r_center * 0.18)), "bold")
        )

        # 4. Letters on Outer Wheel (Plaintext, A-Z)
        r_text_outer = (r_outer + r_inner) / 2
        r_text_inner = (r_inner + r_center) / 2

        for i in range(26):
            angle_deg = i * (360.0 / 26) - 90
            rad = math.radians(angle_deg)

            x_out = cx + r_text_outer * math.cos(rad)
            y_out = cy + r_text_outer * math.sin(rad)

            char_plain = chr(ord('A') + i)
            self.create_text(
                x_out, y_out,
                text=char_plain,
                fill=WHEEL_LETTERING_GREY,
                font=("Helvetica", max(8, int(r_outer * 0.08)), "bold")
            )

            # Letters on Inner Wheel (Shifted Ciphertext)
            shifted_idx = (i + self.shift) % 26
            char_cipher = chr(ord('A') + shifted_idx)
            x_in = cx + r_text_inner * math.cos(rad)
            y_in = cy + r_text_inner * math.sin(rad)

            fill_color = ACCENT_ORANGE if i == 0 else TEXT_PRIMARY
            self.create_text(
                x_in, y_in,
                text=char_cipher,
                fill=fill_color,
                font=("Helvetica", max(8, int(r_outer * 0.08)), "bold")
            )


class PassGenApp(ctk.CTk):
    """Main Windows Application GUI built with CustomTkinter."""

    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("PassGen - Secure Password Vault & Cipher Generator")
        self.geometry("1060x740")
        self.minsize(980, 680)
        self.configure(fg_color=BG_DARK)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        # Session State
        self.current_user = None
        self.is_demo_session = False

        # Load Logo Icon
        self.app_icon_image = None
        self._load_app_icon()

        # Master Container
        self.container = ctk.CTkFrame(self, fg_color=BG_DARK)
        self.container.pack(fill="both", expand=True)

        # Show Auth View Initially
        self.show_login_page()

    def _load_app_icon(self):
        possible_paths = [
            Path(__file__).parent / "static" / "app_icon.png",
            Path(__file__).parent / "public" / "assets" / "aistudio" / "Screenshot_2026-10-17_195343_ffb2d741.png",
        ]
        for p in possible_paths:
            if p.exists():
                try:
                    pil_img = Image.open(str(p)).resize((36, 36), Image.Resampling.LANCZOS)
                    self.app_icon_image = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(36, 36))
                    break
                except Exception:
                    pass

    # =========================================================================
    # AUTHENTICATION VIEW (Demo, User Login, New User)
    # =========================================================================

    def show_login_page(self):
        for widget in self.container.winfo_children():
            widget.destroy()

        self.current_user = None
        self.is_demo_session = False

        center_card = ctk.CTkFrame(
            self.container,
            fg_color=CARD_BG,
            corner_radius=16,
            border_color=BORDER_GREY,
            border_width=1,
            width=480
        )
        center_card.place(relx=0.5, rely=0.5, anchor="center")

        # Header with Logo & Title
        header_frame = ctk.CTkFrame(center_card, fg_color="transparent")
        header_frame.pack(fill="x", padx=30, pady=(30, 16))

        if self.app_icon_image:
            icon_lbl = ctk.CTkLabel(header_frame, image=self.app_icon_image, text="")
            icon_lbl.pack(side="left", padx=(0, 14))

        title_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_box.pack(side="left", fill="both")

        h_title = ctk.CTkLabel(
            title_box,
            text="PassGen",
            font=ctk.CTkFont(family="Helvetica", size=24, weight="bold"),
            text_color=TEXT_PRIMARY
        )
        h_title.pack(anchor="w")

        h_sub = ctk.CTkLabel(
            title_box,
            text="Secure Password Vault & Cipher Generator",
            font=ctk.CTkFont(family="Helvetica", size=12),
            text_color=WHEEL_LETTERING_GREY
        )
        h_sub.pack(anchor="w")

        # Segmented Auth Selector (Demo | User Login | New User)
        self.auth_mode_selector = ctk.CTkSegmentedButton(
            center_card,
            values=["Demo", "User Login", "New User"],
            selected_color=ACCENT_ORANGE,
            selected_hover_color=ACCENT_HOVER,
            unselected_color=ENTRY_BG,
            unselected_hover_color=OUTER_WHEEL_GREY,
            text_color=TEXT_PRIMARY,
            command=self._on_auth_mode_changed
        )
        self.auth_mode_selector.set("Demo")
        self.auth_mode_selector.pack(fill="x", padx=30, pady=(10, 20))

        # Dynamic Auth Form Container
        self.auth_form_frame = ctk.CTkFrame(center_card, fg_color="transparent")
        self.auth_form_frame.pack(fill="x", padx=30, pady=(0, 24))

        self.auth_status_lbl = ctk.CTkLabel(
            center_card,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=ACCENT_ORANGE
        )
        self.auth_status_lbl.pack(pady=(0, 20))

        self._render_demo_auth_view()

    def _on_auth_mode_changed(self, value: str):
        self.auth_status_lbl.configure(text="")
        if value == "Demo":
            self._render_demo_auth_view()
        elif value == "User Login":
            self._render_user_login_view()
        elif value == "New User":
            self._render_new_user_view()

    def _render_demo_auth_view(self):
        for w in self.auth_form_frame.winfo_children():
            w.destroy()

        box = ctk.CTkFrame(self.auth_form_frame, fg_color=ENTRY_BG, corner_radius=10)
        box.pack(fill="x", pady=(0, 16))

        tag = ctk.CTkLabel(
            box,
            text="🚀 Instant Guest Demo",
            font=ctk.CTkFont(family="Helvetica", size=14, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        tag.pack(anchor="w", padx=16, pady=(14, 4))

        info = ctk.CTkLabel(
            box,
            text="Explore the password vault and all 6 cipher engines with sample records. No credentials required.",
            font=ctk.CTkFont(family="Helvetica", size=12),
            text_color=WHEEL_LETTERING_GREY,
            wraplength=380,
            justify="left"
        )
        info.pack(anchor="w", padx=16, pady=(0, 14))

        demo_btn = ctk.CTkButton(
            self.auth_form_frame,
            text="Enter as Demo User",
            height=42,
            fg_color=ACCENT_ORANGE,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Helvetica", size=13, weight="bold"),
            command=self._enter_demo_session
        )
        demo_btn.pack(fill="x")

    def _enter_demo_session(self):
        self.current_user = "demo"
        self.is_demo_session = True
        self.show_main_dashboard()

    def _render_user_login_view(self):
        for w in self.auth_form_frame.winfo_children():
            w.destroy()

        u_lbl = ctk.CTkLabel(self.auth_form_frame, text="Username", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_PRIMARY)
        u_lbl.pack(anchor="w", pady=(0, 4))
        self.login_user_entry = ctk.CTkEntry(self.auth_form_frame, placeholder_text="Enter your username", height=38, fg_color=ENTRY_BG, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.login_user_entry.pack(fill="x", pady=(0, 12))

        p_lbl = ctk.CTkLabel(self.auth_form_frame, text="Master Password", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_PRIMARY)
        p_lbl.pack(anchor="w", pady=(0, 4))
        self.login_pwd_entry = ctk.CTkEntry(self.auth_form_frame, placeholder_text="••••••••", show="•", height=38, fg_color=ENTRY_BG, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.login_pwd_entry.pack(fill="x", pady=(0, 16))
        self.login_pwd_entry.bind("<Return>", lambda e: self._submit_login())

        login_btn = ctk.CTkButton(
            self.auth_form_frame,
            text="🔓 Log In to Vault",
            height=42,
            fg_color=ACCENT_ORANGE,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Helvetica", size=13, weight="bold"),
            command=self._submit_login
        )
        login_btn.pack(fill="x")

    def _submit_login(self):
        u = self.login_user_entry.get().strip()
        p = self.login_pwd_entry.get()
        if not u or not p:
            self.auth_status_lbl.configure(text="Please enter both username and password.", text_color=ACCENT_ORANGE)
            return

        res = engine.authenticate_user(u, p)
        if res.get("success"):
            self.current_user = res.get("username")
            self.is_demo_session = res.get("is_demo", False)
            self.show_main_dashboard()
        else:
            self.auth_status_lbl.configure(text=f"❌ {res.get('message', 'Login failed.')}", text_color="#ef4444")

    def _render_new_user_view(self):
        for w in self.auth_form_frame.winfo_children():
            w.destroy()

        u_lbl = ctk.CTkLabel(self.auth_form_frame, text="Choose Username", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_PRIMARY)
        u_lbl.pack(anchor="w", pady=(0, 4))
        self.reg_user_entry = ctk.CTkEntry(self.auth_form_frame, placeholder_text="e.g. security_master", height=38, fg_color=ENTRY_BG, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.reg_user_entry.pack(fill="x", pady=(0, 12))

        p_lbl = ctk.CTkLabel(self.auth_form_frame, text="Create Master Password", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_PRIMARY)
        p_lbl.pack(anchor="w", pady=(0, 4))
        self.reg_pwd_entry = ctk.CTkEntry(self.auth_form_frame, placeholder_text="Min 4 characters", show="•", height=38, fg_color=ENTRY_BG, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.reg_pwd_entry.pack(fill="x", pady=(0, 16))
        self.reg_pwd_entry.bind("<Return>", lambda e: self._submit_register())

        reg_btn = ctk.CTkButton(
            self.auth_form_frame,
            text="✨ Create New Account",
            height=42,
            fg_color=ACCENT_ORANGE,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Helvetica", size=13, weight="bold"),
            command=self._submit_register
        )
        reg_btn.pack(fill="x")

    def _submit_register(self):
        u = self.reg_user_entry.get().strip()
        p = self.reg_pwd_entry.get()
        if not u or not p:
            self.auth_status_lbl.configure(text="Please fill in both fields.", text_color=ACCENT_ORANGE)
            return

        res = engine.register_user(u, p)
        if res.get("success"):
            self.current_user = res.get("username")
            self.is_demo_session = False
            self.show_main_dashboard()
        else:
            self.auth_status_lbl.configure(text=f"❌ {res.get('message', 'Registration failed.')}", text_color="#ef4444")

    # =========================================================================
    # MAIN DASHBOARD (3 TABS)
    # =========================================================================

    def show_main_dashboard(self):
        for widget in self.container.winfo_children():
            widget.destroy()

        # Top Bar
        top_bar = ctk.CTkFrame(self.container, fg_color=CARD_BG, height=64, corner_radius=0)
        top_bar.pack(fill="x", padx=0, pady=0)
        top_bar.pack_propagate(False)

        top_inner = ctk.CTkFrame(top_bar, fg_color="transparent")
        top_inner.pack(fill="both", expand=True, padx=24)

        # Brand / Title
        left_brand = ctk.CTkFrame(top_inner, fg_color="transparent")
        left_brand.pack(side="left")

        if self.app_icon_image:
            icon_lbl = ctk.CTkLabel(left_brand, image=self.app_icon_image, text="")
            icon_lbl.pack(side="left", padx=(0, 12))

        title_box = ctk.CTkFrame(left_brand, fg_color="transparent")
        title_box.pack(side="left")

        h_title = ctk.CTkLabel(title_box, text="PassGen", font=ctk.CTkFont(family="Helvetica", size=22, weight="bold"), text_color=TEXT_PRIMARY)
        h_title.pack(anchor="w")

        h_sub = ctk.CTkLabel(title_box, text="Secure Password Vault & Cipher Generator (v2)", font=ctk.CTkFont(size=12), text_color=TEXT_PRIMARY)
        h_sub.pack(anchor="w")

        # User profile & logout
        right_box = ctk.CTkFrame(top_inner, fg_color="transparent")
        right_box.pack(side="right")

        user_badge_text = f"User: {self.current_user}" if not self.is_demo_session else "Session: DEMO"
        user_lbl = ctk.CTkLabel(
            right_box,
            text=user_badge_text,
            font=ctk.CTkFont(family="Helvetica", size=13, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        user_lbl.pack(side="left", padx=(0, 14))

        logout_btn = ctk.CTkButton(
            right_box,
            text="🚪 Log Out",
            width=80,
            height=32,
            fg_color=OUTER_WHEEL_GREY,
            hover_color="#ef4444",
            text_color=TEXT_PRIMARY,
            command=self.show_login_page
        )
        logout_btn.pack(side="left")

        # Main Workspace
        workspace = ctk.CTkFrame(self.container, fg_color="transparent")
        workspace.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        # 3 Main Navigation Tabs
        self.nav_tabs = ctk.CTkTabview(
            workspace,
            fg_color=CARD_BG,
            segmented_button_fg_color=ENTRY_BG,
            segmented_button_selected_color=ACCENT_ORANGE,
            segmented_button_selected_hover_color=ACCENT_HOVER,
            segmented_button_unselected_color=ENTRY_BG,
            segmented_button_unselected_hover_color=OUTER_WHEEL_GREY,
            text_color=TEXT_PRIMARY,
            corner_radius=12
        )
        self.nav_tabs.pack(fill="both", expand=True)

        self.tab_vault = self.nav_tabs.add("  1. See the Vault  ")
        self.tab_add = self.nav_tabs.add("  2. Add New Password  ")
        self.tab_export = self.nav_tabs.add("  3. Export Saved Passwords  ")
        self.tab_special = self.nav_tabs.add("  4. Special Access (spl_ppl)  ")

        self._build_vault_tab()
        self._build_add_password_tab()
        self._build_export_tab()
        self._build_special_tab()

    # ---------------------------
    # TAB 1: SEE THE VAULT
    # ---------------------------
    def _build_vault_tab(self):
        parent = self.tab_vault

        header_row = ctk.CTkFrame(parent, fg_color="transparent")
        header_row.pack(fill="x", padx=16, pady=(12, 6))

        cat_lbl = ctk.CTkLabel(
            header_row,
            text="SAVED PASSWORD VAULT",
            font=ctk.CTkFont(family="Helvetica", size=11, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        cat_lbl.pack(side="left")

        refresh_btn = ctk.CTkButton(
            header_row,
            text="🔄 Refresh",
            width=80,
            height=28,
            fg_color=ENTRY_BG,
            hover_color=OUTER_WHEEL_GREY,
            text_color=TEXT_PRIMARY,
            command=self.load_vault_passwords
        )
        refresh_btn.pack(side="right")

        export_csv_btn = ctk.CTkButton(
            header_row,
            text="📊 Export Excel/CSV (vault_records.csv)",
            width=210,
            height=28,
            fg_color=OUTER_WHEEL_GREY,
            hover_color=ACCENT_ORANGE,
            text_color=TEXT_PRIMARY,
            command=self.export_vault_csv
        )
        export_csv_btn.pack(side="right", padx=(0, 8))

        self.vault_scroll = ctk.CTkScrollableFrame(parent, fg_color=ENTRY_BG, corner_radius=8)
        self.vault_scroll.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.load_vault_passwords()

    def load_vault_passwords(self):
        for widget in self.vault_scroll.winfo_children():
            widget.destroy()

        records = engine.get_user_vault(self.current_user)
        if not records:
            empty_lbl = ctk.CTkLabel(
                self.vault_scroll,
                text="Your vault is empty. Click '2. Add New Password' to encrypt and store your first password.",
                text_color=WHEEL_LETTERING_GREY,
                pady=40
            )
            empty_lbl.pack()
            return

        for rec in records:
            card = ctk.CTkFrame(self.vault_scroll, fg_color=CARD_BG, corner_radius=8, border_color=BORDER_GREY, border_width=1)
            card.pack(fill="x", padx=4, pady=6)

            left_info = ctk.CTkFrame(card, fg_color="transparent")
            left_info.pack(side="left", padx=14, pady=10)

            c_type = rec.get("cipher", "")
            method_name = engine.CIPHER_NAMES.get(c_type, f"Method {c_type.upper()}")

            srv_lbl = ctk.CTkLabel(
                left_info,
                text=rec.get("service", "Untitled Service"),
                font=ctk.CTkFont(family="Helvetica", size=14, weight="bold"),
                text_color=TEXT_PRIMARY,
                anchor="w"
            )
            srv_lbl.pack(anchor="w")

            user_meta = ctk.CTkLabel(
                left_info,
                text=f"Username: {rec.get('account_username', self.current_user)}  |  Cipher: {method_name}",
                font=ctk.CTkFont(family="Helvetica", size=11),
                text_color=WHEEL_LETTERING_GREY,
                anchor="w"
            )
            user_meta.pack(anchor="w")

            # Center encrypted / decrypted container
            center_info = ctk.CTkFrame(card, fg_color="transparent")
            center_info.pack(side="left", fill="x", expand=True, padx=10, pady=10)

            ct_text = str(rec.get("cipher_text", ""))
            ct_display_text = f"Ciphertext: {ct_text[:38]}..." if len(ct_text) > 42 else f"Ciphertext: {ct_text}"
            ct_display = ctk.CTkLabel(
                center_info,
                text=ct_display_text,
                font=ctk.CTkFont(family="Courier", size=12, weight="bold"),
                text_color=TEXT_PRIMARY,
                anchor="w"
            )
            ct_display.pack(fill="x")

            dec_display = ctk.CTkLabel(
                center_info,
                text="",
                font=ctk.CTkFont(family="Courier", size=12, weight="bold"),
                text_color="#4ade80",
                anchor="w"
            )
            dec_display.pack(fill="x")

            # Right actions
            actions = ctk.CTkFrame(card, fg_color="transparent")
            actions.pack(side="right", padx=14, pady=10)

            dec_btn = ctk.CTkButton(
                actions,
                text="🔓 Decrypt",
                width=80,
                height=30,
                fg_color=OUTER_WHEEL_GREY,
                hover_color=ACCENT_ORANGE,
                text_color=TEXT_PRIMARY,
                command=lambda r=rec, lbl=dec_display: self._decrypt_record_view(r, lbl)
            )
            dec_btn.pack(side="left", padx=4)

            del_btn = ctk.CTkButton(
                actions,
                text="🗑",
                width=34,
                height=30,
                fg_color=ENTRY_BG,
                hover_color="#ef4444",
                text_color=WHEEL_LETTERING_GREY,
                command=lambda r_id=rec.get("id"): self._delete_vault_record(r_id)
            )
            del_btn.pack(side="left")

    def _decrypt_record_view(self, record: dict, lbl: ctk.CTkLabel):
        decrypted = engine.decode_record(record)
        lbl.configure(text=f"Decrypted: {decrypted}")

    def _delete_vault_record(self, record_id: int):
        if record_id:
            engine.delete_user_password(record_id, self.current_user)
            self.load_vault_passwords()

    # ---------------------------
    # TAB 2: ADD NEW PASSWORD
    # ---------------------------
    def _build_add_password_tab(self):
        parent = self.tab_add

        split_container = ctk.CTkFrame(parent, fg_color="transparent")
        split_container.pack(fill="both", expand=True, padx=16, pady=10)

        # Left Column: Inputs & Encryption Options
        left_form = ctk.CTkFrame(split_container, fg_color="transparent")
        left_form.pack(side="left", fill="both", expand=True, padx=(0, 16))

        cat_lbl = ctk.CTkLabel(
            left_form,
            text="ENCRYPTION METHOD (PASSGEN v2)",
            font=ctk.CTkFont(family="Helvetica", size=11, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        cat_lbl.pack(anchor="w", pady=(0, 4))

        self.cipher_method_selector = ctk.CTkOptionMenu(
            left_form,
            values=CIPHER_CHOICES,
            fg_color=ENTRY_BG,
            button_color=ACCENT_ORANGE,
            button_hover_color=ACCENT_HOVER,
            dropdown_fg_color=CARD_BG,
            dropdown_hover_color=OUTER_WHEEL_GREY,
            text_color=TEXT_PRIMARY,
            height=34,
            command=self._on_add_cipher_method_changed
        )
        self.cipher_method_selector.set(CIPHER_CHOICES[0])
        self.cipher_method_selector.pack(fill="x", pady=(0, 8))

        # Dynamic parameter row (Shift / Keyword / XOR / AES)
        self.add_param_frame = ctk.CTkFrame(left_form, fg_color=ENTRY_BG, corner_radius=8)
        self.add_param_frame.pack(fill="x", pady=(0, 8))

        self.add_param_label = ctk.CTkLabel(
            self.add_param_frame,
            text="Shift Offset (+3):",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=TEXT_PRIMARY
        )
        self.add_param_label.pack(side="left", padx=10, pady=8)

        self.add_param_entry = ctk.CTkEntry(
            self.add_param_frame,
            width=140,
            fg_color=BG_DARK,
            border_color=BORDER_GREY,
            text_color=TEXT_PRIMARY
        )
        self.add_param_entry.insert(0, "3")
        self.add_param_entry.pack(side="left", padx=6, pady=8)
        self.add_param_entry.bind("<KeyRelease>", self._on_add_param_entry_changed)

        self.add_gen_key_btn = ctk.CTkButton(
            self.add_param_frame,
            text="⚡ Random Key",
            width=90,
            height=28,
            fg_color=OUTER_WHEEL_GREY,
            hover_color=ACCENT_ORANGE,
            text_color=TEXT_PRIMARY,
            command=self._generate_random_key_for_method
        )
        # Hidden by default for Caesar
        self.add_gen_key_btn.pack(side="left", padx=6)
        self.add_gen_key_btn.pack_forget()

        # Fields: Service, Username, Password
        fields_cat = ctk.CTkLabel(
            left_form,
            text="CREDENTIAL DETAILS",
            font=ctk.CTkFont(family="Helvetica", size=11, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        fields_cat.pack(anchor="w", pady=(2, 4))

        s_lbl = ctk.CTkLabel(left_form, text="Website or Service Name", font=ctk.CTkFont(size=11), text_color=WHEEL_LETTERING_GREY)
        s_lbl.pack(anchor="w")
        self.add_service_entry = ctk.CTkEntry(left_form, placeholder_text="e.g. Google, GitHub, Work Portal...", height=34, fg_color=ENTRY_BG, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.add_service_entry.pack(fill="x", pady=(0, 6))

        u_lbl = ctk.CTkLabel(left_form, text="Account Username / Email", font=ctk.CTkFont(size=11), text_color=WHEEL_LETTERING_GREY)
        u_lbl.pack(anchor="w")
        self.add_username_entry = ctk.CTkEntry(left_form, placeholder_text="e.g. user@example.com...", height=34, fg_color=ENTRY_BG, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.add_username_entry.pack(fill="x", pady=(0, 6))

        p_lbl = ctk.CTkLabel(left_form, text="Password to Encrypt", font=ctk.CTkFont(size=11), text_color=WHEEL_LETTERING_GREY)
        p_lbl.pack(anchor="w")
        self.add_pwd_entry = ctk.CTkEntry(left_form, placeholder_text="Type password to encrypt...", height=34, fg_color=ENTRY_BG, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.add_pwd_entry.pack(fill="x", pady=(0, 6))
        self.add_pwd_entry.bind("<KeyRelease>", lambda e: self._update_add_preview())

        # Password Quality & Strength Meter (Regex Complexity)
        self.strength_frame = ctk.CTkFrame(left_form, fg_color=ENTRY_BG, corner_radius=8)
        self.strength_frame.pack(fill="x", pady=(0, 8))

        self.strength_header = ctk.CTkFrame(self.strength_frame, fg_color="transparent")
        self.strength_header.pack(fill="x", padx=10, pady=(6, 2))

        self.strength_title_lbl = ctk.CTkLabel(
            self.strength_header,
            text="Password Strength:",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=WHEEL_LETTERING_GREY
        )
        self.strength_title_lbl.pack(side="left")

        self.strength_val_lbl = ctk.CTkLabel(
            self.strength_header,
            text="None (0%)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=WHEEL_LETTERING_GREY
        )
        self.strength_val_lbl.pack(side="right")

        self.strength_bar = ctk.CTkProgressBar(
            self.strength_frame,
            height=6,
            corner_radius=3,
            progress_color=OUTER_WHEEL_GREY,
            fg_color=BG_DARK
        )
        self.strength_bar.set(0.0)
        self.strength_bar.pack(fill="x", padx=10, pady=(0, 4))

        self.criteria_lbl = ctk.CTkLabel(
            self.strength_frame,
            text="○ 8+ Chars   ○ Uppercase (A-Z)   ○ Lowercase (a-z)   ○ Number (0-9)   ○ Symbol (!@#$)",
            font=ctk.CTkFont(size=10),
            text_color=WHEEL_LETTERING_GREY
        )
        self.criteria_lbl.pack(padx=10, pady=(0, 6))

        # Live Ciphertext preview
        preview_cat = ctk.CTkLabel(
            left_form,
            text="ENCRYPTED PREVIEW",
            font=ctk.CTkFont(family="Helvetica", size=11, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        preview_cat.pack(anchor="w", pady=(2, 2))

        self.add_preview_lbl = ctk.CTkLabel(
            left_form,
            text="[Ciphertext will appear here]",
            font=ctk.CTkFont(family="Courier", size=12, weight="bold"),
            text_color=TEXT_PRIMARY,
            anchor="w"
        )
        self.add_preview_lbl.pack(fill="x", pady=(0, 8))

        # Save Button
        save_btn = ctk.CTkButton(
            left_form,
            text="💾 Encrypt & Save to Vault",
            height=38,
            fg_color=ACCENT_ORANGE,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Helvetica", size=13, weight="bold"),
            command=self.save_new_password
        )
        save_btn.pack(fill="x", pady=(2, 0))

        self.add_status_lbl = ctk.CTkLabel(left_form, text="", font=ctk.CTkFont(size=11), text_color="#4ade80")
        self.add_status_lbl.pack(pady=(2, 0))

        # Right Column: Interactive Cipher Dial Visualizer
        right_dial_box = ctk.CTkFrame(split_container, fg_color=CARD_BG, corner_radius=12, width=320)
        right_dial_box.pack(side="right", fill="y")
        right_dial_box.pack_propagate(False)

        d_cat = ctk.CTkLabel(
            right_dial_box,
            text="CIPHER DIAL VISUALIZER",
            font=ctk.CTkFont(family="Helvetica", size=11, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        d_cat.pack(anchor="w", padx=16, pady=(14, 2))

        self.add_dial = CipherDialCanvas(right_dial_box, current_shift=3)
        self.add_dial.pack(padx=12, pady=4, fill="both", expand=True)

        # Dial Controls
        self.dial_ctrls = ctk.CTkFrame(right_dial_box, fg_color="transparent")
        self.dial_ctrls.pack(fill="x", padx=16, pady=(0, 14))

        m_btn = ctk.CTkButton(
            self.dial_ctrls, text="◀ -1", width=50, height=28, fg_color=OUTER_WHEEL_GREY, hover_color=ACCENT_ORANGE, text_color=TEXT_PRIMARY,
            command=lambda: self._adjust_add_shift(-1)
        )
        m_btn.pack(side="left")

        self.add_shift_slider = ctk.CTkSlider(
            self.dial_ctrls, from_=0, to=25, number_of_steps=25,
            button_color=ACCENT_ORANGE, progress_color=ACCENT_ORANGE, fg_color=OUTER_WHEEL_GREY,
            command=self._on_add_slider_moved
        )
        self.add_shift_slider.set(3)
        self.add_shift_slider.pack(side="left", fill="x", expand=True, padx=6)

        p_btn = ctk.CTkButton(
            self.dial_ctrls, text="+1 ▶", width=50, height=28, fg_color=OUTER_WHEEL_GREY, hover_color=ACCENT_ORANGE, text_color=TEXT_PRIMARY,
            command=lambda: self._adjust_add_shift(1)
        )
        p_btn.pack(side="right")

    def _adjust_add_shift(self, delta: int):
        val = (int(self.add_shift_slider.get()) + delta) % 26
        self.add_shift_slider.set(val)
        self._on_add_slider_moved(val)

    def _on_add_slider_moved(self, value):
        val = int(value) % 26
        self.add_dial.set_shift(val)
        choice = self.cipher_method_selector.get()
        if "Caesar" in choice:
            self.add_param_label.configure(text=f"Shift Offset (+{val}):")
            self.add_param_entry.delete(0, "end")
            self.add_param_entry.insert(0, str(val))
        self._update_add_preview()

    def _generate_random_key_for_method(self):
        choice = self.cipher_method_selector.get()
        if "AES" in choice:
            key = engine.generate_random_aes_key(16)
            self.add_param_entry.delete(0, "end")
            self.add_param_entry.insert(0, key)
        elif "XOR" in choice:
            key = engine.generate_random_aes_key(8)
            self.add_param_entry.delete(0, "end")
            self.add_param_entry.insert(0, key)
        self._update_add_preview()

    def _on_add_cipher_method_changed(self, choice: str):
        self.add_gen_key_btn.pack_forget()

        if "Caesar" in choice:
            self.add_param_label.configure(text="Shift Offset (+3):")
            self.add_param_entry.configure(state="normal")
            self.add_param_entry.delete(0, "end")
            self.add_param_entry.insert(0, "3")
            self.add_dial.set_shift(3)
        elif "ROT13" in choice:
            self.add_param_label.configure(text="Fixed ROT13 Shift (+13):")
            self.add_param_entry.delete(0, "end")
            self.add_param_entry.insert(0, "13")
            self.add_param_entry.configure(state="disabled")
            self.add_dial.set_shift(13)
        elif "Vigenère" in choice:
            self.add_param_label.configure(text="Keyword (Letters Only):")
            self.add_param_entry.configure(state="normal")
            self.add_param_entry.delete(0, "end")
            self.add_param_entry.insert(0, "KEY")
            self.add_dial.set_shift(0)
        elif "XOR" in choice:
            self.add_param_label.configure(text="XOR Stream Key:")
            self.add_param_entry.configure(state="normal")
            self.add_param_entry.delete(0, "end")
            self.add_param_entry.insert(0, "PASSGEN_KEY")
            self.add_gen_key_btn.pack(side="left", padx=6)
            self.add_dial.set_shift(0)
        elif "AES" in choice:
            self.add_param_label.configure(text="16-Byte AES Key:")
            self.add_param_entry.configure(state="normal")
            self.add_param_entry.delete(0, "end")
            self.add_param_entry.insert(0, engine.generate_random_aes_key(16))
            self.add_gen_key_btn.pack(side="left", padx=6)
            self.add_dial.set_shift(0)

        self._update_add_preview()

    def _on_add_param_entry_changed(self, event):
        choice = self.cipher_method_selector.get()
        val = self.add_param_entry.get().strip()
        if "Caesar" in choice and val.isdigit():
            shift = int(val) % 26
            self.add_shift_slider.set(shift)
            self.add_dial.set_shift(shift)
            self.add_param_label.configure(text=f"Shift Offset (+{shift}):")
        self._update_add_preview()

    def _update_add_preview(self):
        pwd = self.add_pwd_entry.get()
        strength = engine.analyze_password_strength(pwd)

        # Update real-time password strength meter widgets
        pct = strength.get("percentage", 0) / 100.0
        label = strength.get("label", "None")
        color = strength.get("color", OUTER_WHEEL_GREY)

        self.strength_bar.set(pct)
        self.strength_bar.configure(progress_color=color)
        self.strength_val_lbl.configure(
            text=f"{label} ({strength.get('percentage', 0)}%)",
            text_color=color if label != "None" else WHEEL_LETTERING_GREY
        )

        crit = strength.get("criteria", {})
        c_len = "● 8+ Chars" if crit.get("min_length") else "○ 8+ Chars"
        c_upper = "● Uppercase (A-Z)" if crit.get("has_uppercase") else "○ Uppercase (A-Z)"
        c_lower = "● Lowercase (a-z)" if crit.get("has_lowercase") else "○ Lowercase (a-z)"
        c_num = "● Number (0-9)" if crit.get("has_number") else "○ Number (0-9)"
        c_sym = "● Symbol (!@#$)" if crit.get("has_symbol") else "○ Symbol (!@#$)"

        self.criteria_lbl.configure(
            text=f"{c_len}   {c_upper}   {c_lower}   {c_num}   {c_sym}",
            text_color=TEXT_PRIMARY if pwd else WHEEL_LETTERING_GREY
        )

        if not pwd:
            self.add_preview_lbl.configure(text="[Ciphertext will appear here]", text_color=TEXT_MUTED)
            return

        choice = self.cipher_method_selector.get()
        if "Caesar" in choice:
            try:
                shift = int(self.add_param_entry.get().strip())
            except ValueError:
                shift = 3
            res = engine.caesar_encrypt(pwd, shift=shift, rot13=False)
            ct = res['cipher_text']
        elif "ROT13" in choice:
            res = engine.caesar_encrypt(pwd, shift=13, rot13=True)
            ct = res['cipher_text']
        elif "Vigenère" in choice:
            key = self.add_param_entry.get().strip() or "KEY"
            res = engine.vigenere_encrypt(pwd, key=key)
            ct = res['cipher_text']
        elif "XOR" in choice:
            key = self.add_param_entry.get().strip() or "PASSGEN_KEY"
            ct = engine.xor_stream_encrypt(pwd, key=key)
        elif "AES" in choice:
            key = self.add_param_entry.get().strip() or "1234567890123456"
            aes_res = engine.aes_128_encrypt(pwd, key=key)
            ct = aes_res['cipher_text']
        else:
            ct = pwd

        display_text = f"Ciphertext: {ct[:45]}..." if len(ct) > 48 else f"Ciphertext: {ct}"
        self.add_preview_lbl.configure(text=display_text, text_color=TEXT_PRIMARY)

    def save_new_password(self):
        service = self.add_service_entry.get().strip()
        account_user = self.add_username_entry.get().strip()
        pwd = self.add_pwd_entry.get()

        if not pwd:
            self.add_status_lbl.configure(text="⚠️ Please enter a password to encrypt.", text_color=ACCENT_ORANGE)
            return

        choice = self.cipher_method_selector.get()
        shift = 3
        key = "KEY"

        if "Caesar" in choice:
            cipher_type = "caesar"
            try:
                shift = int(self.add_param_entry.get().strip())
            except ValueError:
                shift = 3
            key = shift
        elif "ROT13" in choice:
            cipher_type = "rot13"
            shift = 13
            key = 13
        elif "Vigenère" in choice:
            cipher_type = "vigenere"
            key = self.add_param_entry.get().strip() or "KEY"
        elif "XOR" in choice:
            cipher_type = "xor"
            key = self.add_param_entry.get().strip() or "PASSGEN_KEY"
        elif "AES" in choice:
            cipher_type = "aes"
            key = self.add_param_entry.get().strip() or "1234567890123456"
        else:
            cipher_type = "caesar"

        new_rec = engine.save_user_password(
            username=self.current_user,
            service_name=service or "General",
            account_username=account_user or self.current_user,
            plaintext_password=pwd,
            cipher_type=cipher_type,
            shift=shift,
            key=key
        )

        self.add_status_lbl.configure(
            text=f"✅ Saved to vault as record #{new_rec.get('id')}!",
            text_color="#4ade80"
        )
        self.add_service_entry.delete(0, "end")
        self.add_username_entry.delete(0, "end")
        self.add_pwd_entry.delete(0, "end")
        self._update_add_preview()
        self.load_vault_passwords()

    # ---------------------------
    # TAB 3: EXPORT SAVED PASSWORDS
    # ---------------------------
    def _build_export_tab(self):
        parent = self.tab_export

        cat_lbl = ctk.CTkLabel(
            parent,
            text="SECURE PASSWORD EXPORT VERIFICATION",
            font=ctk.CTkFont(family="Helvetica", size=11, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        cat_lbl.pack(anchor="w", padx=16, pady=(12, 4))

        desc_lbl = ctk.CTkLabel(
            parent,
            text="To protect your credentials, please verify your login username and password. Upon successful authentication, all corresponding decrypted passwords will be exported.",
            font=ctk.CTkFont(family="Helvetica", size=12),
            text_color=WHEEL_LETTERING_GREY,
            wraplength=700,
            justify="left"
        )
        desc_lbl.pack(anchor="w", padx=16, pady=(0, 14))

        # Verification Box
        verify_box = ctk.CTkFrame(parent, fg_color=ENTRY_BG, corner_radius=8)
        verify_box.pack(fill="x", padx=16, pady=(0, 14))

        u_col = ctk.CTkFrame(verify_box, fg_color="transparent")
        u_col.pack(side="left", fill="x", expand=True, padx=12, pady=12)

        u_label = ctk.CTkLabel(u_col, text="Login Username", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_PRIMARY)
        u_label.pack(anchor="w", pady=(0, 4))

        self.export_user_entry = ctk.CTkEntry(u_col, height=36, fg_color=BG_DARK, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.export_user_entry.insert(0, self.current_user)
        self.export_user_entry.pack(fill="x")

        p_col = ctk.CTkFrame(verify_box, fg_color="transparent")
        p_col.pack(side="left", fill="x", expand=True, padx=12, pady=12)

        p_label = ctk.CTkLabel(p_col, text="Master Password", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_PRIMARY)
        p_label.pack(anchor="w", pady=(0, 4))

        self.export_pwd_entry = ctk.CTkEntry(p_col, show="•", height=36, fg_color=BG_DARK, border_color=BORDER_GREY, text_color=TEXT_PRIMARY)
        self.export_pwd_entry.pack(fill="x")
        self.export_pwd_entry.bind("<Return>", lambda e: self.do_export_verification())

        btn_col = ctk.CTkFrame(verify_box, fg_color="transparent")
        btn_col.pack(side="right", padx=12, pady=(28, 12))

        verify_btn = ctk.CTkButton(
            btn_col,
            text="🔓 Authenticate & Export",
            height=36,
            fg_color=ACCENT_ORANGE,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Helvetica", size=13, weight="bold"),
            command=self.do_export_verification
        )
        verify_btn.pack()

        # Export Output Area
        output_header = ctk.CTkFrame(parent, fg_color="transparent")
        output_header.pack(fill="x", padx=16, pady=(0, 6))

        o_lbl = ctk.CTkLabel(
            output_header,
            text="DECRYPTED EXPORT RECORDS",
            font=ctk.CTkFont(family="Helvetica", size=11, weight="bold"),
            text_color=ACCENT_ORANGE
        )
        o_lbl.pack(side="left")

        self.export_copy_btn = ctk.CTkButton(
            output_header,
            text="📋 Copy All",
            width=80,
            height=28,
            fg_color=OUTER_WHEEL_GREY,
            hover_color=ACCENT_ORANGE,
            text_color=TEXT_PRIMARY,
            state="disabled",
            command=self.copy_export_text
        )
        self.export_copy_btn.pack(side="right", padx=(6, 0))

        self.export_csv_btn = ctk.CTkButton(
            output_header,
            text="📊 Export CSV (Excel)",
            width=130,
            height=28,
            fg_color=OUTER_WHEEL_GREY,
            hover_color=ACCENT_ORANGE,
            text_color=TEXT_PRIMARY,
            state="disabled",
            command=self.save_export_to_csv
        )
        self.export_csv_btn.pack(side="right", padx=(6, 0))

        self.export_save_file_btn = ctk.CTkButton(
            output_header,
            text="💾 Save Text",
            width=80,
            height=28,
            fg_color=ENTRY_BG,
            hover_color=OUTER_WHEEL_GREY,
            text_color=TEXT_PRIMARY,
            state="disabled",
            command=self.save_export_to_file
        )
        self.export_save_file_btn.pack(side="right")

        self.export_result_box = ctk.CTkTextbox(
            parent,
            fg_color=ENTRY_BG,
            border_color=BORDER_GREY,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Courier", size=12),
            wrap="none"
        )
        self.export_result_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.export_result_box.insert("1.0", "Authenticate above to retrieve decrypted passwords.")
        self.export_result_box.configure(state="disabled")

        self.last_exported_records = []

    def do_export_verification(self):
        u = self.export_user_entry.get().strip()
        p = self.export_pwd_entry.get()

        res = engine.export_user_passwords(u, p)
        self.export_result_box.configure(state="normal")
        self.export_result_box.delete("1.0", "end")

        if res.get("success"):
            records = res.get("records", [])
            self.last_exported_records = records

            lines = [
                f"=== PASSGEN SECURE EXPORT: USER '{u}' ===\n",
                f"Export Session: Authorized\n",
                f"Total Records: {len(records)}\n",
                "=" * 70 + "\n\n"
            ]

            if not records:
                lines.append("No saved passwords found in your vault.\n")
            else:
                for r in records:
                    lines.append(
                        f"ID: #{r['id']}  |  Service: {r['service']}\n"
                        f"Account Username:    {r['account_username']}\n"
                        f"Cipher Method:       {r['cipher_method']} (Key: {r['key']})\n"
                        f"Encrypted Password:  {r['encrypted_password']}\n"
                        f"DECRYPTED PASSWORD:  {r['decrypted_password']}\n"
                        f"{'-' * 70}\n\n"
                    )

            self.export_result_box.insert("1.0", "".join(lines))
            self.export_copy_btn.configure(state="normal")
            self.export_csv_btn.configure(state="normal")
            self.export_save_file_btn.configure(state="normal")
        else:
            self.last_exported_records = []
            self.export_result_box.insert(
                "1.0",
                f"❌ ACCESS DENIED\n\n{res.get('message', 'Authentication failed.')}\n\nPlease check your username and master password."
            )
            self.export_copy_btn.configure(state="disabled")
            self.export_csv_btn.configure(state="disabled")
            self.export_save_file_btn.configure(state="disabled")

        self.export_result_box.configure(state="disabled")

    def copy_export_text(self):
        text = self.export_result_box.get("1.0", "end")
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Export", "Decrypted passwords copied to clipboard!")

    def save_export_to_file(self):
        text = self.export_result_box.get("1.0", "end")
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text File", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("Export", f"Saved successfully to {file_path}")

    def save_export_to_csv(self):
        if not self.last_exported_records:
            messagebox.showwarning("Export", "No records to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Spreadsheet", "*.csv"), ("All Files", "*.*")],
            initialfile="vault_records_decrypted.csv"
        )
        if file_path:
            csv_content = engine.export_to_csv_string(self.last_exported_records)
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                f.write(csv_content)
            messagebox.showinfo("Export", f"Excel CSV saved successfully to {file_path}")

    def export_vault_csv(self):
        try:
            csv_content, default_path = engine.generate_vault_records_csv()
            file_path = filedialog.asksaveasfilename(
                title="Save Vault Spreadsheet",
                initialfile="vault_records.csv",
                defaultextension=".csv",
                filetypes=[("CSV Spreadsheet", "*.csv"), ("All Files", "*.*")]
            )
            if file_path:
                with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                    f.write(csv_content)
                messagebox.showinfo("Export", f"Spreadsheet saved successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export vault spreadsheet:\n{e}")

    # ---------------------------
    # TAB 4: SPECIAL ACCESS (spl_ppl)
    # ---------------------------
    def _build_special_tab(self):
        parent = self.tab_special

        container = ctk.CTkFrame(parent, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=16)

        # Header Card
        h_card = ctk.CTkFrame(container, fg_color=ENTRY_BG, corner_radius=12, border_color=BORDER_GREY, border_width=1)
        h_card.pack(fill="x", pady=(0, 16), padx=4)

        h_inner = ctk.CTkFrame(h_card, fg_color="transparent")
        h_inner.pack(fill="x", padx=18, pady=14)

        t_lbl = ctk.CTkLabel(
            h_inner,
            text="SPECIAL ACCESS GATEWAY (spl_ppl)",
            font=ctk.CTkFont(family="Helvetica", size=13, weight="bold"),
            text_color="#a855f7"
        )
        t_lbl.pack(anchor="w")

        sub_lbl = ctk.CTkLabel(
            h_inner,
            text="Class database and privileged user checkpoint ported from PassGen v2.",
            font=ctk.CTkFont(size=12),
            text_color=WHEEL_LETTERING_GREY
        )
        sub_lbl.pack(anchor="w", pady=(2, 0))

        # Authentication Input Row
        auth_row = ctk.CTkFrame(container, fg_color=CARD_BG, corner_radius=10, border_color=BORDER_GREY, border_width=1)
        auth_row.pack(fill="x", pady=(0, 14), padx=4)

        prompt_lbl = ctk.CTkLabel(
            auth_row,
            text="Welcome. Your good name please?",
            font=ctk.CTkFont(family="Helvetica", size=13, weight="bold"),
            text_color=TEXT_PRIMARY
        )
        prompt_lbl.pack(anchor="w", padx=16, pady=(12, 6))

        input_box = ctk.CTkFrame(auth_row, fg_color="transparent")
        input_box.pack(fill="x", padx=16, pady=(0, 10))

        self.special_name_entry = ctk.CTkEntry(
            input_box,
            placeholder_text="Enter name (e.g. Jenifa, Maria, Devananda)...",
            fg_color=ENTRY_BG,
            border_color=BORDER_GREY,
            text_color=TEXT_PRIMARY,
            height=36
        )
        self.special_name_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.special_name_entry.bind("<Return>", lambda e: self._submit_special_name())

        submit_btn = ctk.CTkButton(
            input_box,
            text="Verify Access",
            fg_color="#a855f7",
            hover_color="#9333ea",
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(weight="bold"),
            width=120,
            height=36,
            command=self._submit_special_name
        )
        submit_btn.pack(side="left")

        # Preset Shortcut Chips
        preset_row = ctk.CTkFrame(auth_row, fg_color="transparent")
        preset_row.pack(fill="x", padx=16, pady=(0, 12))

        preset_lbl = ctk.CTkLabel(preset_row, text="Known identities:", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED)
        preset_lbl.pack(side="left", padx=(0, 8))

        for p_name, p_role in [("Jenifa", "Master Privileges"), ("Maria", "Denied"), ("Devananda", "Denied")]:
            chip = ctk.CTkButton(
                preset_row,
                text=f"{p_name} ({p_role})",
                font=ctk.CTkFont(size=11),
                height=24,
                fg_color=ENTRY_BG,
                hover_color=OUTER_WHEEL_GREY,
                text_color=TEXT_PRIMARY,
                command=lambda n=p_name: self._set_special_preset(n)
            )
            chip.pack(side="left", padx=4)

        # Result Display Area
        self.special_result_frame = ctk.CTkFrame(container, fg_color=ENTRY_BG, corner_radius=12, border_color=BORDER_GREY, border_width=1)
        self.special_result_frame.pack(fill="both", expand=True, padx=4)

        self._render_special_empty_state()

    def _set_special_preset(self, name: str):
        self.special_name_entry.delete(0, "end")
        self.special_name_entry.insert(0, name)
        self._submit_special_name()

    def _render_special_empty_state(self):
        for w in self.special_result_frame.winfo_children():
            w.destroy()
        lbl = ctk.CTkLabel(
            self.special_result_frame,
            text="Enter your name above to query the PassGen special permissions gateway.",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(size=13)
        )
        lbl.pack(expand=True, pady=40)

    def _submit_special_name(self):
        name = self.special_name_entry.get().strip()
        if not name:
            return

        for w in self.special_result_frame.winfo_children():
            w.destroy()

        res = engine.check_special_access(name)
        status = res.get("status")

        if status == "denied":
            card = ctk.CTkFrame(self.special_result_frame, fg_color="#2b1114", border_color="#ef4444", border_width=1, corner_radius=10)
            card.pack(fill="x", padx=20, pady=20)
            ctk.CTkLabel(
                card,
                text="🛑 ACCESS DENIED",
                font=ctk.CTkFont(family="Helvetica", size=16, weight="bold"),
                text_color="#ef4444"
            ).pack(anchor="w", padx=18, pady=(16, 4))
            ctk.CTkLabel(
                card,
                text="Access restricted. You don't have decode permissions.",
                font=ctk.CTkFont(size=13),
                text_color="#fca5a5"
            ).pack(anchor="w", padx=18, pady=(0, 16))

        elif status == "jenifa":
            card = ctk.CTkFrame(self.special_result_frame, fg_color="#1e1829", border_color="#a855f7", border_width=1, corner_radius=10)
            card.pack(fill="both", expand=True, padx=16, pady=16)

            h_box = ctk.CTkFrame(card, fg_color="transparent")
            h_box.pack(fill="x", padx=18, pady=(14, 10))

            ctk.CTkLabel(
                h_box,
                text="👑 Hi ma'am, What would you like to do?",
                font=ctk.CTkFont(family="Helvetica", size=15, weight="bold"),
                text_color="#d8b4fe"
            ).pack(side="left")

            btn_box = ctk.CTkFrame(card, fg_color="transparent")
            btn_box.pack(fill="x", padx=18, pady=(0, 12))

            t_btn = ctk.CTkButton(
                btn_box,
                text="1. Decode Records (Total List 'T')",
                fg_color="#7e22ce",
                hover_color="#6b21a8",
                text_color=TEXT_PRIMARY,
                height=32,
                command=self._show_jenifa_decoded_records
            )
            t_btn.pack(side="left", padx=(0, 10))

            exp_btn = ctk.CTkButton(
                btn_box,
                text="2. Export Decrypted Excel (vault_records_decrypted.csv)",
                fg_color="#10b981",
                hover_color="#059669",
                text_color=TEXT_PRIMARY,
                height=32,
                command=self._export_jenifa_csv
            )
            exp_btn.pack(side="left")

            self.jenifa_content_scroll = ctk.CTkScrollableFrame(card, fg_color=ENTRY_BG, corner_radius=8)
            self.jenifa_content_scroll.pack(fill="both", expand=True, padx=18, pady=(0, 16))
            self._show_jenifa_decoded_records()

        else:
            card = ctk.CTkFrame(self.special_result_frame, fg_color="#261b14", border_color="#f59e0b", border_width=1, corner_radius=10)
            card.pack(fill="x", padx=20, pady=20)
            ctk.CTkLabel(
                card,
                text="⚠️ SYBAU",
                font=ctk.CTkFont(family="Helvetica", size=16, weight="bold"),
                text_color="#f59e0b"
            ).pack(anchor="w", padx=18, pady=(16, 4))
            ctk.CTkLabel(
                card,
                text=f"'{name}' not recognized in class database security records.",
                font=ctk.CTkFont(size=13),
                text_color="#fde68a"
            ).pack(anchor="w", padx=18, pady=(0, 16))

    def _show_jenifa_decoded_records(self):
        for w in self.jenifa_content_scroll.winfo_children():
            w.destroy()

        records = engine.get_all_decoded_vault_records()
        if not records:
            ctk.CTkLabel(
                self.jenifa_content_scroll,
                text="No records currently saved in vault.",
                text_color=TEXT_MUTED
            ).pack(pady=20)
            return

        for r in records:
            row = ctk.CTkFrame(self.jenifa_content_scroll, fg_color=CARD_BG, corner_radius=8, border_color=BORDER_GREY, border_width=1)
            row.pack(fill="x", padx=4, pady=4)

            top = ctk.CTkFrame(row, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(8, 2))

            ctk.CTkLabel(
                top,
                text=f"#{r['id']}  {r['cipher_name']}",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=ACCENT_ORANGE
            ).pack(side="left")

            ctk.CTkLabel(
                top,
                text=f"Key: {r['key']}",
                font=ctk.CTkFont(size=11),
                text_color=TEXT_MUTED
            ).pack(side="right")

            mid = ctk.CTkFrame(row, fg_color="transparent")
            mid.pack(fill="x", padx=12, pady=(0, 8))

            ctk.CTkLabel(
                mid,
                text=f"Ciphertext: {r['cipher_text']}",
                font=ctk.CTkFont(family="Courier", size=11),
                text_color=TEXT_PRIMARY
            ).pack(anchor="w")

            ctk.CTkLabel(
                mid,
                text=f"Plaintext:  {r['plain_text']}",
                font=ctk.CTkFont(family="Courier", size=11, weight="bold"),
                text_color="#10b981"
            ).pack(anchor="w")

    def _export_jenifa_csv(self):
        try:
            csv_content, _ = engine.generate_jenifa_decrypted_csv()
            file_path = filedialog.asksaveasfilename(
                title="Save Decrypted Excel Spreadsheet",
                initialfile="vault_records_decrypted.csv",
                defaultextension=".csv",
                filetypes=[("CSV Spreadsheet", "*.csv"), ("All Files", "*.*")]
            )
            if file_path:
                with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                    f.write(csv_content)
                messagebox.showinfo("Export Successful", f"Decrypted Excel spreadsheet generated!\nSaved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export decrypted spreadsheet:\n{e}")


def launch():
    app = PassGenApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
