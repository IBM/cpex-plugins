use crate::config::{LimitMode, OutputLengthGuardConfig};

const MAX_NUMERIC_STRING_LENGTH: usize = 50;
const BOUNDARY_CHARS: &[char] = &[
    ' ', '\t', '\n', '\r', '.', ',', ';', ':', '!', '?', '-', '—', '–', '/', '\\', '(', ')', '[',
    ']', '{', '}',
];

pub fn evaluate_text_limits(
    length: usize,
    token_count: usize,
    cfg: &OutputLengthGuardConfig,
) -> (bool, bool) {
    match cfg.limit_mode {
        LimitMode::Character => {
            let below_min = cfg.min_chars > 0 && length < cfg.min_chars as usize;
            let above_max = cfg.max_chars.is_some_and(|max| length > max as usize);
            (below_min, above_max)
        }
        LimitMode::Token => {
            let below_min = cfg.min_tokens > 0 && token_count < cfg.min_tokens as usize;
            let above_max = cfg.max_tokens.is_some_and(|max| token_count > max as usize);
            (below_min, above_max)
        }
    }
}

pub fn estimate_tokens(text: &str, chars_per_token: u64) -> usize {
    let safe_chars_per_token = if chars_per_token == 0 {
        4
    } else {
        chars_per_token as usize
    };
    text.chars().count() / safe_chars_per_token
}

pub fn find_word_boundary(value: &str, cut: usize, max_chars: usize) -> usize {
    if value.is_empty() || cut == 0 {
        return cut;
    }

    let chars: Vec<char> = value.chars().collect();
    let cut = cut.min(chars.len());
    let min_search = cut.saturating_sub(max_chars / 5);

    for i in (min_search..cut).rev() {
        if BOUNDARY_CHARS.contains(&chars[i]) {
            return i + 1;
        }
    }

    cut
}

pub fn truncate(
    value: &str,
    max_chars: Option<u32>,
    ellipsis: &str,
    word_boundary: bool,
    max_tokens: Option<u32>,
    chars_per_token: u8,
    max_text_length: u32,
    limit_mode: LimitMode,
) -> String {
    let ell = ellipsis;
    let chars: Vec<char> = value.chars().collect();

    if limit_mode == LimitMode::Token {
        if let Some(max_tokens) = max_tokens {
            if max_tokens > 0 {
                let safe_chars_per_token = chars_per_token.max(1) as usize;
                let estimated_tokens = chars.len() / safe_chars_per_token;

                if estimated_tokens > max_tokens as usize {
                    let capped_len = chars.len().min(max_text_length as usize);
                    let mut cut = capped_len.min(max_tokens as usize * safe_chars_per_token);

                    if word_boundary && cut > 0 {
                        cut = find_word_boundary(value, cut, cut);
                    }

                    let prefix: String = chars[..cut].iter().collect();
                    return format!("{prefix}{ell}");
                }
            }
        }
    }

    if limit_mode != LimitMode::Character {
        return value.to_string();
    }
    // if max_chars is None or 0 return entire text
    if max_chars.is_none_or(|max_char| max_char == 0) {
        return value.to_string();
    }
    let max_chars = max_chars.unwrap_or(0) as usize;
    if chars.len() <= max_chars {
        return value.to_string();
    }

    let ell_len = ell.chars().count();
    if ell_len >= max_chars {
        return chars[..max_chars].iter().collect();
    }

    let mut cut = max_chars - ell_len;
    if word_boundary && cut > 0 {
        cut = find_word_boundary(value, cut, max_chars);
    }

    let prefix: String = chars[..cut].iter().collect();
    format!("{prefix}{ell}")
}

pub fn is_numeric_string(text: &str) -> bool {
    if text.len() > MAX_NUMERIC_STRING_LENGTH {
        return false;
    }

    match text.parse::<f64>() {
        Ok(value) => value.is_finite(),
        Err(_) => false,
    }
}
