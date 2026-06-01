use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

fn is_lazy_field_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "LazyField";
        }
    }
    false
}

/// `#[derive(AksharaDocument)]` automatically generates the physical layout
/// schema for a struct, mapping its fields to Merkle-DAG coordinates.
#[proc_macro_derive(
    AksharaDocument,
    attributes(block, collection, lazy, chunked, collaborative_text)
)]
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
    let mut serialize_calls = Vec::new();
    let mut deserialize_calls = Vec::new();

    for field in fields {
        let field_ident = field.ident.as_ref().unwrap();
        let field_name = field_ident.to_string();

        let mut mode = quote!(::akshara::schema::BlockMode::Block); // Default
        let mut is_lazy = quote!(false);
        let mut adapter = None;

        for attr in &field.attrs {
            if attr.path().is_ident("collection") {
                mode = quote!(::akshara::schema::BlockMode::Collection);
                adapter = Some(quote!(::akshara::layout::CollectionLayout));
            } else if attr.path().is_ident("lazy") {
                is_lazy = quote!(true);
            } else if attr.path().is_ident("chunked") {
                mode = quote!(::akshara::schema::BlockMode::Chunked);
                adapter = Some(quote!(::akshara::layout::ChunkedLayout));
            } else if attr.path().is_ident("collaborative_text") {
                mode = quote!(::akshara::schema::BlockMode::CollaborativeText);
                adapter = Some(quote!(::akshara::layout::TextLayout));
            } else if attr.path().is_ident("block") {
                mode = quote!(::akshara::schema::BlockMode::Block);
                adapter = Some(quote!(::akshara::layout::StandaloneLayout));
            }
        }

        let adapter = adapter.unwrap_or(quote!(::akshara::layout::StandaloneLayout));
        let is_lazy_field = is_lazy_field_type(&field.ty);

        field_descriptors.push(quote! {
            ::akshara::schema::FieldDescriptor {
                path: #field_name.to_string(),
                mode: #mode,
                is_lazy: #is_lazy,
            }
        });

        if is_lazy_field {
            deserialize_calls.push(quote! {
                let field_path = format!("{}/{}", doc_path, #field_name);
                let walker = ::akshara_aadhaara::GraphWalker::new(store);
                if let Ok(address) = walker.resolve_path(graph_id, *content_root, &field_path, key).await {
                    self.#field_ident.set_address(address);
                }
            });
        } else {
            serialize_calls.push(quote! {
                let field_path = format!("{}/{}", doc_path, #field_name);
                let addr = #adapter::serialize(
                    &self.#field_ident,
                    graph_id,
                    key,
                    signer,
                    store,
                    &field_path,
                )
                .await?;
                fields.push((#field_name.to_string(), addr));
            });

            deserialize_calls.push(quote! {
                let field_path = format!("{}/{}", doc_path, #field_name);
                let walker = ::akshara_aadhaara::GraphWalker::new(store);
                if let Ok(address) = walker.resolve_path(graph_id, *content_root, &field_path, key).await {
                    self.#field_ident = #adapter::deserialize(
                        &address,
                        graph_id,
                        key,
                        store,
                    )
                    .await?;
                }
            });
        }
    }

    // 2. Generate the Trait implementation
    let expanded = quote! {
        #[::async_trait::async_trait]
        impl ::akshara::schema::AksharaDocument for #name {
            fn schema() -> ::akshara::schema::DocumentSchema {
                ::akshara::schema::DocumentSchema {
                    type_name: stringify!(#name).to_string(),
                    version: 1,
                    fields: vec![
                        #(#field_descriptors),*
                    ],
                }
            }

            fn to_bytes(&self) -> Result<Vec<u8>, ::akshara_aadhaara::AksharaError> {
                ::akshara_aadhaara::to_canonical_bytes(self)
            }

            async fn serialize_fields<S: ::akshara_aadhaara::GraphStore + ?Sized>(
                &self,
                graph_id: &::akshara_aadhaara::GraphId,
                key: &::akshara_aadhaara::GraphKey,
                signer: &::akshara_aadhaara::SecretIdentity,
                store: &S,
                doc_path: &str,
            ) -> Result<Vec<(String, ::akshara_aadhaara::Address)>, ::akshara_aadhaara::AksharaError> {
                use ::akshara::layout::BlockLayout;
                let mut fields = Vec::new();
                #(#serialize_calls)*
                Ok(fields)
            }

            async fn deserialize_fields<S: ::akshara_aadhaara::GraphStore + ?Sized>(
                &mut self,
                graph_id: &::akshara_aadhaara::GraphId,
                key: &::akshara_aadhaara::GraphKey,
                store: &S,
                doc_path: &str,
                content_root: &::akshara_aadhaara::BlockId,
            ) -> Result<(), ::akshara_aadhaara::AksharaError> {
                use ::akshara::layout::BlockLayout;
                #(#deserialize_calls)*
                Ok(())
            }
        }
    };

    TokenStream::from(expanded)
}
