use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// `#[derive(AksharaDocument)]` automatically generates the physical layout
/// schema for a struct, mapping its fields to Merkle-DAG coordinates.
#[proc_macro_derive(AksharaDocument, attributes(block, collection, lazy, chunked))]
pub fn derive_akshara_document(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // 1. Identify all fields and their physical modes
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("AksharaDocument only supports structs with named fields."),
        },
        _ => panic!("AksharaDocument only supports structs."),
    };

    let mut field_descriptors = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap().to_string();

        let mut mode = quote!(::akshara_schema::BlockMode::Block); // Default
        let mut is_lazy = quote!(false);

        for attr in &field.attrs {
            if attr.path().is_ident("collection") {
                mode = quote!(::akshara_schema::BlockMode::Collection);
            } else if attr.path().is_ident("lazy") {
                is_lazy = quote!(true);
            } else if attr.path().is_ident("chunked") {
                mode = quote!(::akshara_schema::BlockMode::Chunked);
            } else if attr.path().is_ident("block") {
                mode = quote!(::akshara_schema::BlockMode::Block);
            }
        }

        field_descriptors.push(quote! {
            ::akshara_schema::FieldDescriptor {
                path: #field_name.to_string(),
                mode: #mode,
                is_lazy: #is_lazy,
            }
        });
    }

    // 2. Generate the Trait implementation
    let expanded = quote! {
        impl ::akshara_schema::AksharaDocument for #name {
            fn schema() -> ::akshara_schema::DocumentSchema {
                ::akshara_schema::DocumentSchema {
                    type_name: stringify!(#name).to_string(),
                    version: 1,
                    fields: vec![
                        #(#field_descriptors),*
                    ],
                }
            }

            fn to_bytes(&self) -> Result<Vec<u8>, ::akshara_schema::AksharaError> {
                ::akshara_schema::to_canonical_bytes(self)
            }
        }
    };

    TokenStream::from(expanded)
}
