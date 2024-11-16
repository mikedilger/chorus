use crate::error::Error;
use futures::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyDataStream, BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::fs::File;
use tokio_util::io::{InspectReader, ReaderStream, StreamReader};

mod hash_output;
pub use hash_output::HashOutput;

pub struct FileStore {
    pub base: PathBuf,
    pub temp: PathBuf,
}

impl FileStore {
    pub async fn new<P: AsRef<Path>>(base: P) -> Result<FileStore, Error> {
        let base = base.as_ref().to_owned();

        let temp = {
            let mut temp = base.clone();
            temp.push("temp");
            temp
        };

        if !fs::try_exists(&temp).await? {
            fs::create_dir_all(&temp).await?;
        }

        Ok(FileStore { base, temp })
    }

    fn tmpfile(&self) -> PathBuf {
        let mut tf = self.temp.clone();
        let nonce = textnonce::TextNonce::new();
        tf.push(&nonce.0);
        tf
    }

    /// Store a file in storage, streamed from a hyper BoxBody
    ///
    /// Returns it's HashOutput by which it can be later retrieved or deleted.
    pub async fn store(&self, data: BoxBody<Bytes, Error>) -> Result<HashOutput, Error> {
        use bitcoin_hashes::sha256;
        use std::io::Write; // for hash_engine.write_all()

        // We will download into a temporary file (as we don't know the hash yet)
        let temppathbuf = self.tmpfile();
        let mut tempfile = File::options()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temppathbuf)
            .await?;

        // Convert the BoxBody into a Data Stream
        let body_stream = BodyDataStream::new(data);

        // Convert the Data Stream into something that is AsyncRead (over bytes)
        let stream_reader = StreamReader::new(body_stream);

        // Wrap this in something that lets us inspect the content so we can hash it
        // as it comes in
        let mut hash_engine = sha256::HashEngine::default();
        let mut inspect_reader = InspectReader::new(stream_reader, |bytes: &[u8]| {
            hash_engine.write_all(bytes).unwrap(); // I don't think hashing will fail
        });

        // Copy the data into the tempfile (hashing as we go)
        tokio::io::copy(&mut inspect_reader, &mut tempfile).await?;

        // Finish the hash
        let hash = HashOutput::from_engine(hash_engine);

        // Compute the proper path
        let pathbuf = hash.to_pathbuf(&self.base);

        // If it already exists
        if fs::try_exists(&pathbuf).await? {
            // Just clean up
            fs::remove_file(&temppathbuf).await?;

            return Ok(hash);
        }

        // Make the parent directory
        fs::create_dir_all(pathbuf.parent().unwrap()).await?;

        // Move the file
        fs::rename(&temppathbuf, &pathbuf).await?;

        Ok(hash)
    }

    /// Retrieve a file from storage by its HashOutput, streamed to a hyper BoxBoxy
    pub async fn retrieve(&self, hash: HashOutput) -> Result<BoxBody<Bytes, Error>, Error> {
        // Compute the path
        let pathbuf = hash.to_pathbuf(&self.base);

        // Open the file
        let file = File::open(&pathbuf).await?;

        // Convert the AsyncRead file into a Stream
        let reader_stream = ReaderStream::new(file);

        // Convert the Stream into a Body
        let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));

        // Box the body, mapping the error
        let boxed_body = BodyExt::map_err(stream_body, |e| e.into()).boxed();

        Ok(boxed_body)
    }

    /// Check if a file exists and provide it's metadata (including .len())
    pub async fn metadata(&self, hash: HashOutput) -> Result<Metadata, Error> {
        // Compute the path
        let pathbuf = hash.to_pathbuf(&self.base);

        Ok(tokio::fs::metadata(&pathbuf).await?)
    }

    /// Delete a file from storage by its HashOutput
    pub async fn delete(&self, hash: HashOutput) -> Result<(), Error> {
        // Compute the path
        let pathbuf = hash.to_pathbuf(&self.base);

        // Delete the file
        tokio::fs::remove_file(&pathbuf).await?;

        Ok(())
    }
}
