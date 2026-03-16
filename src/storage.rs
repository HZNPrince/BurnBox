use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

// Trait for blob storage — abstraction so we can swap disk for S3 later
#[async_trait::async_trait]
pub trait BlobStorage: Send + Sync {
    async fn save(&self, id: Uuid, data: &[u8]) -> Result<String>;
    async fn load(&self, path: &str) -> Result<Vec<u8>>;
    async fn delete(&self, path: &str) -> Result<()>;
}

pub struct LocalStorage {
    base_dir: PathBuf,
}

impl LocalStorage {
    pub async fn new(base_dir: &str) -> Result<Self> {
        let path = PathBuf::from(base_dir);

        fs::create_dir_all(&path)
            .await
            .context("Failed to create Storage Directory")?;

        Ok(LocalStorage { base_dir: path })
    }
}

#[async_trait::async_trait]
impl BlobStorage for LocalStorage {
    async fn save(&self, id: Uuid, data: &[u8]) -> Result<String> {
        let file_path = self.base_dir.join(id.to_string());
        fs::write(&file_path, data)
            .await
            .context("Failed to write Blob to disk")?;

        // Return the path as a string to store in DB
        Ok(file_path.to_string_lossy().to_string())
    }

    async fn load(&self, path: &str) -> Result<Vec<u8>> {
        fs::read(path)
            .await
            .context("Failed to read blob from disk")
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let path = Path::new(path);
        if path.exists() {
            fs::remove_file(path)
                .await
                .context("Failed to delete blob from disk")?;
        }
        Ok(())
    }
}
