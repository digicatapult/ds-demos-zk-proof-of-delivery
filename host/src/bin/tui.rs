// Adapted from
// https://github.com/ratatui/ratatui/blob/9713828c838d567ec4d782869f1e2f267cc022b3/ratatui-widgets/examples/list.rs
// with the following licence

// The MIT License (MIT)

// Copyright (c) 2016-2022 Florian Dehau
// Copyright (c) 2023-2025 The Ratatui Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! # [Ratatui] `List` example
//!
//! The latest version of this example is available in the [widget examples] folder in the
//! repository.
//!
//! Please note that the examples are designed to be run against the `main` branch of the Github
//! repository. This means that you may not be able to compile with the latest release version on
//! crates.io, or the one that you have installed locally.
//!
//! See the [examples readme] for more information on finding examples that match the version of the
//! library you are using.
//!
//! [Ratatui]: https://github.com/ratatui/ratatui
//! [widget examples]: https://github.com/ratatui/ratatui/blob/main/ratatui-widgets/examples
//! [examples readme]: https://github.com/ratatui/ratatui/blob/main/examples/README.md

use borsh::de::BorshDeserialize;
use borsh::BorshSerialize;
use color_eyre::Result;
use crossterm::event::{self, KeyCode, KeyEvent};
use host::{compute_fingerprint, prove_token_validation};
use jwt_core::PublicOutput;
use jwt_core::{CustomClaims, Issuer};
use methods::VERIFY_TOKEN_WITH_SOME_KEY_ID;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Flex, Layout, Margin, Offset, Rect};
use ratatui::style::{Color, Modifier, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Clear, List, ListState, Paragraph, Widget, Wrap};
use ratatui::{DefaultTerminal, Frame};
use risc0_zkvm::Receipt;
use std::fs::File;
use std::io::prelude::*;
use uuid::Uuid;

fn main() -> Result<()> {
    color_eyre::install()?;

    let gen_and_sign_form = InputForm {
        fields: Vec::from([
            StringField::new("Issuer ID", "Coffee Chain 1".to_owned()),
            StringField::new("Supplier ID", "Coffee Supplier".to_owned()),
            StringField::new("Product", "raw coffee beans".to_owned()),
            StringField::new("Quantity (kg)", "1000".to_owned()),
            StringField::new("Cost (£)", "4000.00".to_owned()),
            StringField::new(
                "Path to signing key",
                "./test_data/coffee_company_sk.jwk".to_owned(),
            ),
            StringField::new(
                "Path to output proof of delivery",
                "./proof_of_delivery.jwt".to_owned(),
            ),
        ]),
        focus: 0,
    };

    let prove_form = InputForm {
        fields: Vec::from([
            StringField::new(
                "Path to proof of delivery",
                "./proof_of_delivery.jwt".to_owned(),
            ),
            StringField::new(
                "Path to verification key 1",
                "./test_data/other_pk_1.jwk".to_owned(),
            ),
            StringField::new(
                "Path to verification key 2",
                "./test_data/coffee_company_pk.jwk".to_owned(),
            ),
            StringField::new(
                "Path to verification key 3",
                "./test_data/other_pk_2.jwk".to_owned(),
            ),
            StringField::new(
                "Path to output Zero-Knowledge Proof of Delivery",
                "./zkpod.bin".to_owned(),
            ),
        ]),
        focus: 0,
    };

    let verify_form = InputForm {
        fields: Vec::from([StringField::new(
            "Path to Proof of Delivery",
            "./zkpod.bin".to_owned(),
        )]),
        focus: 0,
    };

    let app = App {
        state: AppState::Running,
        window: AppWindow::Home,
        home: SelectScreen::default(),
        gen_and_sign_form,
        prove_form,
        verify_form,
        result_text: "".to_string(),
        show_popup: false,
    };

    match ratatui::run(|terminal| app.run(terminal)) {
        Ok(()) => println!("Exited"),
        Err(err) => eprintln!("{err}"),
    }
    Ok(())
}

pub struct App {
    state: AppState,
    window: AppWindow,
    home: SelectScreen,
    gen_and_sign_form: InputForm,
    prove_form: InputForm,
    verify_form: InputForm,
    result_text: String,
    show_popup: bool,
}

#[derive(PartialEq, Eq)]
enum AppState {
    Running,
    Cancelled,
    Submitted,
}

#[derive(PartialEq, Eq)]
enum AppWindow {
    Home,
    Gen,
    Prove,
    Verify,
    Result,
}

impl App {
    pub fn run(mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while self.state != AppState::Cancelled {
            while self.state != AppState::Submitted {
                terminal.draw(|frame: &mut Frame<'_>| self.render(frame))?;
                self.handle_events()?;
                if self.state == AppState::Cancelled {
                    return Ok(());
                }
            }
            // Now submitted
            match self.window {
                AppWindow::Home => (),
                AppWindow::Gen => {
                    let args = self.gen_and_sign_form.get_form_fields();

                    let mut invoice_claims = CustomClaims::new();
                    invoice_claims.add("reference".to_string(), Uuid::new_v4().to_string(), false);
                    invoice_claims.add("issuer_id".to_string(), args[0].clone(), true);
                    invoice_claims.add("subject_id".to_string(), args[1].clone(), false);
                    invoice_claims.add("product".to_string(), args[2].clone(), false);
                    invoice_claims.add("quantity".to_string(), args[3].clone(), false);
                    invoice_claims.add("cost".to_string(), args[4].clone(), true);

                    let invoice_claims_string =
                        serde_json::to_string_pretty(&invoice_claims).unwrap();

                    let mut f = File::open(&args[5])
                        .expect("Please provide issuer secret key in PEM format as first argument");
                    let mut secret_key = "".to_string();
                    f.read_to_string(&mut secret_key).unwrap();

                    let claims: CustomClaims = serde_json::from_str(&invoice_claims_string)
                        .expect("Could not parse invoice claims");

                    let iss = secret_key
                        .parse::<Issuer>()
                        .expect("failed to create issuer from secret key");
                    let token = iss
                        .generate_token(&claims)
                        .expect("failed to generate token");

                    let mut f = File::create(&args[6]).expect("Could not create JWT file");
                    f.write_all(&token.as_bytes())
                        .expect("Could not write to file");
                    self.window = AppWindow::Home;
                    self.state = AppState::Running;
                }
                AppWindow::Prove => {
                    let args = self.prove_form.get_form_fields();

                    let mut f = File::open(&args[0]).expect("Could not find token file");
                    let mut token = String::new();
                    f.read_to_string(&mut token)
                        .expect("Could not parse token from file");

                    let mut pks: Vec<String> = Vec::new();

                    for i in 1..4 {
                        let mut f = File::open(&args[i]).expect("Could not find public key file");
                        let mut pk = String::new();
                        f.read_to_string(&mut pk)
                            .expect("Could not parse public key from file");
                        pks.push(pk);
                    }

                    let (receipt, _journal) = prove_token_validation(token, &pks);

                    let mut f = File::create(&args[4]).expect("Could not create receipt file");
                    let mut serialized_receipt = Vec::new();
                    receipt
                        .serialize(&mut serialized_receipt)
                        .expect("Could not serialise the receipt");
                    f.write_all(&serialized_receipt)
                        .expect("Could not write receipt to file");
                    self.window = AppWindow::Home;
                    self.state = AppState::Running;
                }
                AppWindow::Verify => {
                    let args = self.verify_form.get_form_fields();

                    let mut f = File::open(&args[0]).expect("Could not find receipt file");
                    let mut receipt = Vec::new();
                    f.read_to_end(&mut receipt)
                        .expect("Could not parse token from file");

                    let receipt = Receipt::try_from_slice(&receipt)
                        .expect("Could not deserialise bytes as receipt");

                    let res = receipt.verify(VERIFY_TOKEN_WITH_SOME_KEY_ID);
                    if res.is_ok() {
                        self.result_text = String::from("Verification succeeded!");
                        let public_outputs: PublicOutput = receipt
                            .journal
                            .decode()
                            .expect("Could not decode receipt journal");
                        self.result_text.push_str("\nThe prover has a JWT signed by the secret key corresponding to one of the following public keys: ");

                        let pk_digests: Vec<String> = public_outputs
                            .pks
                            .into_iter()
                            .map(|pk| compute_fingerprint(pk))
                            .collect();
                        self.result_text
                            .push_str(format!("{:#?}", pk_digests).as_str());

                        self.result_text.push_str("\nThe JWT attests to the following public claims (and 0 or more undisclosed private claims): ");
                        self.result_text.push_str(
                            format!("{:}", public_outputs.claims.pretty_print()).as_str(),
                        );
                    }
                    self.show_popup = true;
                    self.window = AppWindow::Result;
                    self.state = AppState::Running;
                }
                AppWindow::Result => {
                    self.show_popup = false;
                    self.window = AppWindow::Home;
                    self.state = AppState::Running;
                }
            };
        }
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {
        if self.show_popup {
            self.render_result(frame);
        } else {
            match self.window {
                AppWindow::Home => self.home.render(frame),
                AppWindow::Gen => self.gen_and_sign_form.render(frame),
                AppWindow::Prove => self.prove_form.render(frame),
                AppWindow::Verify => self.verify_form.render(frame),
                AppWindow::Result => self.render_result(frame),
            };
        }
    }

    fn handle_events(&mut self) -> Result<Vec<String>> {
        if let Some(key) = event::read()?.as_key_press_event() {
            match key.code {
                KeyCode::Esc => {
                    self.state = match self.window {
                        AppWindow::Home => AppState::Cancelled,
                        _ => {
                            self.window = AppWindow::Home;
                            self.show_popup = false;
                            AppState::Running
                        }
                    }
                }
                KeyCode::Enter => match self.window {
                    AppWindow::Gen | AppWindow::Prove | AppWindow::Verify | AppWindow::Result => {
                        self.state = AppState::Submitted
                    }
                    AppWindow::Home => match self.home.on_key_press(key) {
                        Some(result) => {
                            self.window = match result {
                                0 => AppWindow::Gen,
                                1 => AppWindow::Prove,
                                2 => AppWindow::Verify,
                                _ => AppWindow::Home,
                            }
                        }
                        _ => (),
                    },
                },
                _ => match self.window {
                    AppWindow::Gen => self.gen_and_sign_form.on_key_press(key),
                    AppWindow::Prove => self.prove_form.on_key_press(key),
                    AppWindow::Verify => self.verify_form.on_key_press(key),
                    AppWindow::Home => {
                        if self.home.on_key_press(key) == Some(410) {
                            self.state = AppState::Cancelled;
                        };
                    }
                    _ => {
                        self.window = AppWindow::Home;
                        self.show_popup = false;
                        self.state = AppState::Running;
                    }
                },
            }
        }
        Ok(Vec::new())
    }

    fn render_result(&self, frame: &mut Frame) {
        let area = frame.area();

        let block = Block::bordered().title("Result").on_black();
        let area = percentage_area(area, 80, 80);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);

        let result = percentage_area(area, 90, 90);

        let binding = self.result_text.clone();
        let text: Text = binding.split('\n').collect();
        let paragraph = Paragraph::new(text.slow_blink()).wrap(Wrap { trim: true });
        frame.render_widget(paragraph, result);
    }
}

fn percentage_area(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

struct SelectScreen {
    list_state: ListState,
}

impl Default for SelectScreen {
    fn default() -> Self {
        let mut list_state = ListState::default();
        list_state.select_first();
        SelectScreen { list_state }
    }
}

impl SelectScreen {
    /// Render the UI with various lists.
    fn render(&mut self, frame: &mut Frame) {
        let constraints = [
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ];
        let layout = Layout::vertical(constraints).spacing(1);
        let [top, first, _second] = frame.area().inner(Margin::new(2, 2)).layout(&layout);

        let title = Line::from_iter([
            Span::from("Zero-Knowledge Proof of Delivery").bold(),
            Span::from(" (Press 'q' to quit and arrow keys to navigate)"),
        ]);
        frame.render_widget(title.centered(), top);

        self.render_list(frame, first);
    }

    pub fn render_list(&mut self, frame: &mut Frame, area: Rect) {
        let items = [
            "Generate and sign Proof of Delivery",
            "Generate a Zero-Knowledge Proof of Delivery",
            "Verify a Zero-Knowledge Proof of Delivery",
        ];
        let list = List::new(items)
            .style(Color::White)
            .highlight_style(Modifier::REVERSED)
            .highlight_symbol("> ");

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn on_key_press(&mut self, event: KeyEvent) -> Option<usize> {
        match event.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.list_state.select_next();
                None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.list_state.select_previous();
                None
            }
            KeyCode::Char('q') | KeyCode::Esc => Some(410),
            KeyCode::Enter => self.list_state.selected(),
            _ => None,
        }
    }
}

struct InputForm {
    focus: usize,
    fields: Vec<StringField>,
}

impl InputForm {
    // Handle focus navigation or pass the event to the focused field.
    fn on_key_press(&mut self, event: KeyEvent) {
        match event.code {
            KeyCode::Tab | KeyCode::Down => {
                if self.focus < self.fields.len() - 1 {
                    self.focus += 1;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if self.focus > 0 {
                    self.focus -= 1;
                }
            }
            _ => self.fields[self.focus].on_key_press(event),
        }
    }

    fn render(&self, frame: &mut Frame) {
        let area = frame.area();

        let block = Block::bordered().title("Press <Enter> to submit").on_blue();
        let area = percentage_area(area, 80, 80);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);

        let layout = Layout::vertical(Constraint::from_lengths(vec![1; self.fields.len()]));
        let areas = area.inner(Margin::new(2, 2)).layout_vec(&layout);
        for index in 0..self.fields.len() {
            frame.render_widget(&self.fields[index], areas[index]);
        }

        let cursor_position = areas[self.focus] + self.fields[self.focus].cursor_offset();

        frame.set_cursor_position(cursor_position);
    }

    pub fn get_form_fields(&self) -> Vec<String> {
        self.fields.iter().map(|e| e.value.clone()).collect()
    }
}

#[derive(Debug)]
struct StringField {
    label: &'static str,
    value: String,
}

impl StringField {
    const fn new(label: &'static str, value: String) -> Self {
        Self { label, value }
    }

    fn on_key_press(&mut self, event: KeyEvent) {
        match event.code {
            KeyCode::Char(c) => self.value.push(c),
            KeyCode::Backspace => {
                self.value.pop();
            }
            _ => {}
        }
    }

    const fn cursor_offset(&self) -> Offset {
        let x = (self.label.len() + self.value.len() + 2) as i32;
        Offset::new(x, 0)
    }
}

impl Widget for &StringField {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let layout = Layout::horizontal([
            Constraint::Length(self.label.len() as u16 + 2),
            Constraint::Fill(1),
        ]);
        let [label_area, value_area] = area.layout(&layout);
        let label = Line::from_iter([self.label, ": "]).bold();
        label.render(label_area, buf);
        self.value.clone().render(value_area, buf);
    }
}
