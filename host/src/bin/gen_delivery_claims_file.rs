use clap::Parser;
use jwt_core::CustomClaims;
//use serde::Serialize;
use std::io::prelude::*;
use uuid::Uuid;

// #[derive(Serialize)]
// pub struct InvoiceClaims {
//     reference: String, // uuid
//     issuer_id: String,
//     subject_id: String,
//     product: String,
//     quantity: i32,
//     cost: f64,
// }

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "./invoice_claims.json")]
    path_to_claims_file: String,

    #[arg(short, long, default_value = "Coffee Chain 1")]
    issuer_id: String,

    #[arg(short, long, default_value = "Coffee Supplier")]
    subject_id: String,

    #[arg(short, long, default_value = "raw coffee beans")]
    product: String,

    #[arg(short, long, default_value = "1000")]
    quantity: i32,

    #[arg(short, long, default_value = "4000.00")]
    cost: f64,
}

fn main() {
    let args = Args::parse();

    let mut invoice_claims = CustomClaims::new();
    invoice_claims.add("reference".to_string(), Uuid::new_v4().to_string(), false);
    invoice_claims.add("issuer_id".to_string(), args.issuer_id, true);
    invoice_claims.add("subject_id".to_string(), args.subject_id, false);
    invoice_claims.add("product".to_string(), args.product, false);
    invoice_claims.add("quantity".to_string(), args.quantity.to_string(), false);
    invoice_claims.add("cost".to_string(), args.cost.to_string(), true);

    let invoice_claims_string = serde_json::to_string_pretty(&invoice_claims).unwrap();

    let mut f =
        std::fs::File::create(&args.path_to_claims_file).expect("Could not create claims file");
    f.write_all(&invoice_claims_string.as_bytes())
        .expect("Could not write to file");
}
