🌐 [English](README.md) | [Français](README.fr.md) | [日本語](README.ja.md)

# Wall Of Patents - 404CTF

## チャレンジ概要

**PatentVault** は、ユーザー(本物の認証はなく、セッション内の名前のみで識別される)が
`POST /post_patent` を通じて「特許」をアーカイブ形式でアップロードでき(サーバー側で
`app/uploads/` に展開される)、`GET /comment` でランダムなコメントを取得できる
Flaskサービスである。**FLAG** は初回起動時にデータベースに挿入され、通常は
推測すべき `seed` ウィンドウに従ってコメント(`bot_outputs`)を選ぶボットの仕組みを
通じてしか間接的にアクセスできない(この一連の流れを完全に迂回できない限りは)。

## 脆弱性

注目すべきエントリーポイントはアーカイブの展開処理(`app/utils.py`)である:

```python
allowed_extensions = {'zip', 'gz', 'xz'}

def sanitize_filename(filename):
     blacklist = ["../", "..\\",  ".\\", "//", "..", "\\\\"]
     for pattern in blacklist:
        filename = filename.replace(pattern, "")
     while filename.startswith("/") or filename.startswith("\\"):
        filename = filename[1:]
     return filename

def extract_tar_archive(file, path='app/uploads/'):
    tar = tarfile.open(fileobj=file)
    for member in tar.getmembers():
         clean_name = sanitize_filename(member.name)
         member.name = clean_name
         tar.extract(member, path=path, filter='fully_trusted')
```

二つの欠陥が組み合わさっている:

1. **`sanitize_filename` は `member.name`(アーカイブ内エントリのパス)しかクリーニングせず、
   `member.linkname`(シンボリックリンクの **ターゲット**)は一切処理しない**。そのため、
   パストラバーサル対策のブラックリストはシンボリックリンクに対しては完全に無力となる。
   名前自体は無害だが、ターゲットがファイルシステム上の任意の場所を指す *symlink* 型の
   エントリを作成できてしまう。

2. 展開処理は **`filter='fully_trusted'`** で行われており、これは(PEP 706で導入された
   `data`/`tar` フィルタとは異なり)任意のシンボリックリンク作成も、シンボリックリンクを
   経由する書き込みもブロックしない。リンクが作成されると、その後に続くアーカイブ内の
   メンバーで、パスが *そのリンクを経由する* ものは、リンクが実際に指す場所に展開される
   (通常のファイルシステムのパス解決による)。しかも、これはOSがパスを解決するため、
   Pythonコード側の `sanitize_filename` を再度通過することはない。

**結果として、Flaskプロセスの権限(`Dockerfile` によると UID `65534`、`/app` の所有者であり、
自身のソースコードへの書き込みには十分)に限定された、任意ファイル書き込みプリミティブが
得られる。**

### ターゲット: `app/database.py`

`app/database.py` はアプリケーションがインポートする通常のPythonモジュールである
(`from app.database import ...`)。これを上書きでき、かつサーバーがそのモジュールを
**リロード** すれば、アプリのコンテキストで任意のコードが実行できる。

ところで、`app.py` はFlaskを `debug=True` で起動している:

```python
app.run(host="0.0.0.0", port=3000, debug=True)
```

**Werkzeugリローダー** はプロジェクト内の `.py` ファイルを監視しており、変更が検知されると
自動的にサーバーを再起動する。つまり `app/database.py` を上書きして数秒待つだけで、
悪意のあるコードがロードされ実行される。

### 攻撃チェーン

1. 以下を含む `.tar.gz` アーカイブを構築する:
   - 名前(サニタイズ済みなので無害)はそのままだが、`linkname`(一切フィルタされない)を
     通じてアプリケーションの `app/` ディレクトリ(展開先フォルダ `app/uploads/` からの
     相対パス)を指す **symlink** エントリ。
   - そのシンボリックリンクを **経由する** パスを持ち、`database.py` で終わる、
     差し替えモジュールを内容とする通常ファイルエントリ。
2. このアーカイブを `POST /post_patent`(セッション名だけで「認証」されており、誰でも
   アクセス可能)経由でアップロードする。
3. 展開時に `tarfile` がシンボリックリンクを作成し、続けて悪意のあるファイルを
   そのリンクを *通して* 書き込む: `app/database.py` がディスク上で上書きされる。
4. Flaskのリローダー(`debug=True`)が変更を検知し、悪意のある `database.py` を
   ロードした状態でプロセスを再起動する。
5. 悪意のある `database.py` は `search_comments()` を再定義し、`bot_outputs` から
   ランダムなコメントを取得する代わりに、直接 `os.environ["FLAG"]` を返すようにする。
6. 単純な `GET /comment?name=...`(ルート `get_comment` → `search_comments()`)で、
   ボットも `seed` テーブルも待つ・操作する必要なく、フラグがそのままJSONで返される。

これは、**ボット/seed/`bot_outputs` というミニプロトコル全体を迂回する** 見事な方法である。
ボットが公開する正確なウィンドウ(`compute_range`)を計算してFLAGを含むレコードに
たどり着くことを期待する代わりに、データベースを読むはずの関数自体を、`FLAG` 環境変数を
読む関数に丸ごと置き換えてしまうのである。

## ペイロード(`evil_database.py`)

`app/database.py` の代わりに注入する最小限のモジュール:

```python
import os

def search_comments():
    flag = os.environ.get("FLAG", "404CTF{not_found}")
    return [{"id": 157, "comment": flag}]
```

> 注: アプリは `/comment` ルートのために `search_comments` しか必要としないため、
> 最小限のスタブで十分である(本物のモジュールの他の関数、すなわち `init_db`、`search_patents`、
> `add_patent`、`add_comment`、`change_seed` は、アプリが既に初期化されセッションが
> 既に開かれた後は呼び出されない)。

## 攻略スクリプト(`solver.py`)

`create_session()` がランダムな名前でセッションを開き、`generate_exploit_tar()` が
アーカイブを構築し(シンボリックリンク `link` → `app-flask/app`、その背後に悪意のある
`database.py` を配置)、`upload_exploit()` がそれを `POST /post_patent` 経由で送信し、
`get_flag()` がサーバーの再起動を待ってから(`time.sleep(5)`、再起動中にリクエストが
当たった場合はリトライ)、`/comment` に問い合わせて直接フラグを返す。

```
$ python3 solver.py
404CTF{...}
```
