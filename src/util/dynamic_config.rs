use std::fs;
use std::sync::Arc;

use crate::prelude::*;
use arc_swap::ArcSwap;
use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{de::DeserializeOwned, Serialize};
use std::convert::TryFrom;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

const RENEW_RETRY_TIMES: usize = 10;
const RENEW_AFTER_SECONDS: std::time::Duration = std::time::Duration::from_secs(5);

pub struct DynamicConfig<
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
    Y: TryFrom<T, Error = Error> + Send + Sync + 'static,
> {
    source: String,
    data: ArcSwap<(T, Y)>,
}

impl<
        T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
        Y: TryFrom<T, Error = Error> + Send + Sync + 'static,
    > DynamicConfig<T, Y>
{
    fn load(file: &str) -> Result<(T, Y)> {
        let text = fs::read_to_string(file)?;
        let parsed: T = serde_yaml::from_str(&text)?;
        let processed = Y::try_from(parsed.clone())?;
        Ok((parsed, processed))
    }

    fn refresh(&self) -> Result<(T, Y)> {
        info!("Refreshing configuration");
        for i in 0..RENEW_RETRY_TIMES {
            info!("Trying {}th time ...", i);
            match Self::load(&self.source) {
                Ok(config) => {
                    warn!("Refresh finished successfully on {}th try!", i);
                    return Ok(config);
                }
                Err(e) => {
                    warn!("Refresh failed: {}", e);
                }
            }
            std::thread::sleep(RENEW_AFTER_SECONDS);
        }
        error!("All {} attempts failed!", RENEW_RETRY_TIMES);
        Err(anyhow!("could not reload config"))
    }

    fn watch(self) {
        let (tx, rx) = channel();

        let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_secs(2)).unwrap();
        thread::spawn(move || {
            watcher
                .watch(&*self.source, RecursiveMode::NonRecursive)
                .unwrap();

            loop {
                match rx.recv() {
                    Ok(DebouncedEvent::Write(_)) => {
                        info!(" * {} written; refreshing configuration ...", self.source);
                        match self.refresh() {
                            Ok(data) => {
                                self.data.swap(Arc::new(data));
                                info!("configuration refreshed!");
                            }
                            Err(e) => {
                                error!("could not reload config, try to modify again: {:?}", e);
                            }
                        }
                    }

                    Err(e) => error!("watch error: {:?}", e),

                    e => {
                        // Ignore event
                        info!("watcher captured event {:?}", e);
                    }
                }
            }
        });
    }

    pub fn new(file: String, watched: bool) -> Result<DynamicConfig<T, Y>> {
        let data = Self::load(&file)?;
        let config = DynamicConfig {
            source: file,
            data: ArcSwap::new(Arc::new(data)),
        };
        if watched {
            let watch_proxy = DynamicConfig {
                source: config.source.clone(),
                data: config.data.clone(),
            };
            watch_proxy.watch();
        }
        Ok(config)
    }

    pub fn get(&self) -> Arc<(T, Y)> {
        self.data.load().clone()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use tempfile::{NamedTempFile};
    use serde::{Deserialize};

    #[derive(Serialize, Deserialize, Clone)]
    struct ConfigYaml {
        pub foo: String
    }

    struct ConfigObj {}

    impl TryFrom<ConfigYaml> for ConfigObj {
        type Error = Error;

        fn try_from(_: ConfigYaml) -> Result<ConfigObj> {
            Ok(ConfigObj{})
        } 

    }

    #[test]
    fn test_valid_config_yaml() {
        let mut tmp = NamedTempFile::new().unwrap();
        if let Ok(_) = tmp.write_all("foo: bar".as_bytes()) {
            let _: DynamicConfig<ConfigYaml, ConfigObj> =
                DynamicConfig::new(String::from(
                    tmp.into_temp_path().as_os_str().to_str().unwrap()),
                    false).unwrap();
        } else {
            panic!("Failed to write tmp yaml file");
        }
    }

    #[test]
    #[should_panic(expected = "missing field `foo` at line 1 column 4")]
    fn test_invalid_yaml() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all("bla: bla".as_bytes()).unwrap();
        let r: DynamicConfig<ConfigYaml, ConfigObj> = DynamicConfig::new(String::from(
            tmp.into_temp_path().as_os_str().to_str().unwrap()),
            false).unwrap();
    }
}
